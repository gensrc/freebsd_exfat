/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/disk.h>
#include <sys/endian.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fsck_exfat.h"
#include "fsutil.h"

/*
 * Write 12 sectors of boot region data to disk at byte offset.
 *
 * Returns true on complete write, false otherwise.
 */
static bool
write_boot_region(int fd, const uint8_t *region, size_t size, off_t offset)
{
	ssize_t n;

	n = pwrite(fd, region, size, offset);
	return (n == (ssize_t)size);
}

/*
 * Verify and repair Main and Backup Boot Regions per Spec §3.
 *
 * Validates VBR signatures, geometry parameters, sector shifts, and 32-bit
 * boot checksums for both regions.  Repairs corrupted regions from the valid
 * counterpart.
 *
 * Returns FSOK, FSBOOTMOD, or FSFATAL on unrecoverable boot sector error.
 */
int
check_boot(struct exfat_chk *chk)
{
	uint8_t boot_buf[1U << EXFAT_MAX_SECTOR_SHIFT];
	struct exfat_boot_sector bs;
	struct stat sb;
	uint8_t *region = NULL;
	uint8_t *csum_sec = NULL;
	size_t i, probe_size;
	ssize_t n;
	off_t mediasize;
	uint64_t heap_sectors, min_fat_sectors;
	uint32_t main_csum, backup_csum, sec_size;
	u_int dev_secsize;
	int mod = FSOK;
	bool backup_ok = true, drive_bad, main_ok = true, main_vbr_valid = true;
	bool mbz_bad, res_bad, vbr_sanitized = false;

	/*
	 * Phase 1: Sector 0 read and signature verification.
	 *
	 * Determine the underlying device sector size (defaulting to 512 bytes
	 * for image files) to ensure I/O requests satisfy character device
	 * sector-alignment constraints (e.g. 4Kn media).  Read the primary boot
	 * sector and validate jump instructions, filesystem name ("EXFAT   "),
	 * and 0xAA55 signature (Spec Section 3.1).  If the primary boot sector
	 * is corrupted, probe candidate sector sizes to recover volume
	 * geometry from the Backup Boot Sector (Spec Section 3.1).
	 */
	dev_secsize = 0;
	if (ioctl(chk->fd, DIOCGSECTORSIZE, &dev_secsize) != 0 ||
	    dev_secsize == 0)
		dev_secsize = 1U << EXFAT_MIN_SECTOR_SHIFT;
	probe_size = MAX(dev_secsize, sizeof(bs));
	if (probe_size > sizeof(boot_buf))
		probe_size = sizeof(boot_buf);

	n = pread(chk->fd, boot_buf, probe_size, 0);
	if (n == (ssize_t)probe_size)
		memcpy(&bs, boot_buf, sizeof(bs));
	if (n != (ssize_t)probe_size ||
	    bs.bs_jmp_boot[0] != EXFAT_BOOT_JMP_0 ||
	    bs.bs_jmp_boot[1] != EXFAT_BOOT_JMP_1 ||
	    bs.bs_jmp_boot[2] != EXFAT_BOOT_JMP_2 ||
	    memcmp(bs.bs_fs_name, EXFAT_FS_NAME, sizeof(bs.bs_fs_name)) != 0 ||
	    le16toh(bs.bs_boot_signature) != EXFAT_BOOT_SIGNATURE) {
		main_vbr_valid = false;
		/* Attempt to recover geometry from Backup Boot Sector */
		bool backup_found = false;
		struct exfat_boot_sector bbs;

		for (int shift = EXFAT_MIN_SECTOR_SHIFT;
		    shift <= EXFAT_MAX_SECTOR_SHIFT; shift++) {
			size_t bsize = 1U << shift;
			off_t backup_offset;

			if (bsize < probe_size)
				continue;
			backup_offset = (off_t)EXFAT_BACKUP_BOOT_SECTOR <<
			    shift;
			n = pread(chk->fd, boot_buf, bsize, backup_offset);
			if (n != (ssize_t)bsize)
				continue;
			memcpy(&bbs, boot_buf, sizeof(bbs));
			if (bbs.bs_jmp_boot[0] == EXFAT_BOOT_JMP_0 &&
			    bbs.bs_jmp_boot[1] == EXFAT_BOOT_JMP_1 &&
			    bbs.bs_jmp_boot[2] == EXFAT_BOOT_JMP_2 &&
			    memcmp(bbs.bs_fs_name, EXFAT_FS_NAME,
			    sizeof(bbs.bs_fs_name)) == 0 &&
			    le16toh(bbs.bs_boot_signature) ==
			    EXFAT_BOOT_SIGNATURE &&
			    bbs.bs_bytes_per_sector_shift == shift) {
				bs = bbs;
				backup_found = true;
				break;
			}
		}

		if (backup_found) {
			pwarn("Primary boot sector is invalid, using backup "
			    "boot sector\n");
			main_ok = false;
			mod |= FSERROR;
		} else {
			pwarn("Invalid primary and backup boot sectors\n");
			return (FSFATAL);
		}
	}

	/*
	 * Phase 2: Structural VBR parameter and geometry validation.
	 *
	 * Verify MustBeZero fields (Spec Section 3.1.3), sector/cluster shift
	 * bounds (Spec Section 3.1.14 & 3.1.15), number of FATs, cluster count,
	 * and heap alignment.
	 */
	drive_bad = (bs.bs_drive_select != 0x00 &&
	    bs.bs_drive_select != 0x80);
	mbz_bad = false;
	for (i = 0; i < sizeof(bs.bs_must_be_zero); i++) {
		if (bs.bs_must_be_zero[i] != 0) {
			mbz_bad = true;
			break;
		}
	}
	res_bad = false;
	for (i = 0; i < sizeof(bs.bs_reserved); i++) {
		if (bs.bs_reserved[i] != 0) {
			res_bad = true;
			break;
		}
	}

	if (mbz_bad || res_bad || drive_bad) {
		if (mbz_bad)
			pwarn("Non-zero byte in must_be_zero field "
			    "(Spec §3.1.3)\n");
		if (res_bad)
			pwarn("Non-zero byte in boot reserved field "
			    "(Spec §3.1.19)\n");
		if (drive_bad)
			pwarn("Invalid DriveSelect: 0x%02x (must be 0x00 or "
			    "0x80 per Spec §3.1.17)\n", bs.bs_drive_select);
		if (ask(1, "Fix boot sector reserved and must_be_zero "
		    "fields")) {
			if (mbz_bad)
				memset(bs.bs_must_be_zero, 0,
				    sizeof(bs.bs_must_be_zero));
			if (res_bad)
				memset(bs.bs_reserved, 0,
				    sizeof(bs.bs_reserved));
			if (drive_bad)
				bs.bs_drive_select = 0x80;
			vbr_sanitized = true;
			main_ok = false;
			backup_ok = false;
			mod |= FSBOOTMOD;
		} else
			mod |= FSERROR;
	}

	chk->boot.sector_shift = bs.bs_bytes_per_sector_shift;
	chk->boot.cluster_shift = bs.bs_sectors_per_cluster_shift;

	if (chk->boot.sector_shift < EXFAT_MIN_SECTOR_SHIFT ||
	    chk->boot.sector_shift > EXFAT_MAX_SECTOR_SHIFT) {
		pwarn("Invalid sector shift %u (must be 9 to 12)\n",
		    chk->boot.sector_shift);
		return (FSFATAL);
	}

	if (chk->boot.sector_shift + chk->boot.cluster_shift >
	    EXFAT_MAX_CLUSTER_SHIFT) {
		pwarn("Cluster size exceeds 32 MiB maximum "
		    "(sector_shift %u, cluster_shift %u)\n",
		    chk->boot.sector_shift, chk->boot.cluster_shift);
		return (FSFATAL);
	}

	chk->boot.sector_size = 1U << chk->boot.sector_shift;
	chk->boot.cluster_size =
	    chk->boot.sector_size << chk->boot.cluster_shift;
	sec_size = chk->boot.sector_size;

	if (chk->boot.sector_size < dev_secsize) {
		pwarn("Sector size %u is smaller than device sector size %u\n",
		    chk->boot.sector_size, dev_secsize);
		return (FSFATAL);
	}

	chk->boot.volume_length = le64toh(bs.bs_volume_length);
	chk->boot.fat_offset = le32toh(bs.bs_fat_offset);
	chk->boot.fat_length = le32toh(bs.bs_fat_length);
	chk->boot.cluster_heap_offset = le32toh(bs.bs_cluster_heap_offset);
	chk->boot.cluster_count = le32toh(bs.bs_cluster_count);
	chk->boot.root_dir_cluster = le32toh(bs.bs_root_dir_cluster);
	chk->boot.volume_serial = le32toh(bs.bs_volume_serial);
	chk->boot.fs_revision = le16toh(bs.bs_fs_revision);
	chk->boot.volume_flags = le16toh(bs.bs_volume_flags);
	chk->boot.number_of_fats = bs.bs_number_of_fats;
	chk->boot.percent_in_use = bs.bs_percent_in_use;

	if (chk->boot.number_of_fats != 1 && chk->boot.number_of_fats != 2) {
		pwarn("Invalid number of FATs: %u\n", chk->boot.number_of_fats);
		return (FSFATAL);
	}

	if ((chk->boot.fs_revision >> 8) != EXFAT_FS_REVISION_MAJOR) {
		pwarn("Unsupported file system revision %u.%02u "
		    "(expected major %u)\n",
		    chk->boot.fs_revision >> 8, chk->boot.fs_revision & 0xFF,
		    EXFAT_FS_REVISION_MAJOR);
		return (FSFATAL);
	}

	if (chk->boot.number_of_fats == 1 &&
	    (chk->boot.volume_flags & EXFAT_VOL_ACTIVE_FAT) != 0) {
		pwarn("ActiveFat flag set when NumberOfFats is 1 "
		    "(Spec §3.1.13.1)\n");
		if (ask(1, "Clear invalid ActiveFat flag")) {
			chk->boot.volume_flags &= ~EXFAT_VOL_ACTIVE_FAT;
			bs.bs_volume_flags = htole16(chk->boot.volume_flags);
			vbr_sanitized = true;
			main_ok = false;
			backup_ok = false;
			mod |= FSBOOTMOD;
		} else
			mod |= FSERROR;
	}

	if ((chk->boot.volume_flags & EXFAT_VOL_CLEAR_TO_ZERO) != 0) {
		pwarn("ClearToZero flag set (volume requires reformat or "
		    "clearing per Spec §3.1.13.4)\n");
		if (ask(1, "Clear invalid ClearToZero flag")) {
			chk->boot.volume_flags &= ~EXFAT_VOL_CLEAR_TO_ZERO;
			bs.bs_volume_flags = htole16(chk->boot.volume_flags);
			vbr_sanitized = true;
			main_ok = false;
			backup_ok = false;
			mod |= FSBOOTMOD;
		} else
			mod |= FSERROR;
	}

	if ((chk->boot.volume_flags & ~0x000F) != 0) {
		pwarn("Invalid reserved bits in VolumeFlags: 0x%04x "
		    "(Spec §3.1.13.5)\n",
		    chk->boot.volume_flags & ~0x000F);
		if (ask(1, "Clear invalid VolumeFlags reserved bits")) {
			chk->boot.volume_flags &= 0x000F;
			bs.bs_volume_flags = htole16(chk->boot.volume_flags);
			vbr_sanitized = true;
			main_ok = false;
			backup_ok = false;
			mod |= FSBOOTMOD;
		} else
			mod |= FSERROR;
	}

	if (chk->boot.cluster_count < 1 ||
	    chk->boot.cluster_count > EXFAT_MAX_CLUSTER_COUNT) {
		pwarn("Invalid cluster count: %u\n", chk->boot.cluster_count);
		return (FSFATAL);
	}

	if (chk->boot.percent_in_use > 100 &&
	    chk->boot.percent_in_use != EXFAT_PERCENT_IN_USE_UNKNOWN) {
		pwarn("Invalid PercentInUse: %u (must be 0-100 or 0xFF)\n",
		    chk->boot.percent_in_use);
		if (ask(1, "Fix invalid PercentInUse")) {
			chk->boot.percent_in_use = 0;
			bs.bs_percent_in_use = 0;
			vbr_sanitized = true;
			main_ok = false;
			backup_ok = false;
			mod |= (FSBOOTMOD | FSDIRTY);
		} else
			mod |= FSERROR;
	}

	if (chk->boot.fat_offset < EXFAT_MIN_FAT_OFFSET) {
		pwarn("FAT offset (%u sectors) overlaps boot regions "
		    "(minimum %u sectors)\n",
		    chk->boot.fat_offset, EXFAT_MIN_FAT_OFFSET);
		return (FSFATAL);
	}

	if (chk->boot.cluster_heap_offset <
	    chk->boot.fat_offset +
	    (uint64_t)chk->boot.fat_length * chk->boot.number_of_fats) {
		pwarn("Cluster heap offset (%u) overlaps with FAT table\n",
		    chk->boot.cluster_heap_offset);
		return (FSFATAL);
	}

	/* FAT length must be sufficient to cover all clusters (Spec §3.1.7) */
	min_fat_sectors = howmany((uint64_t)(chk->boot.cluster_count + 2) *
	    sizeof(uint32_t), chk->boot.sector_size);
	if (chk->boot.fat_length < min_fat_sectors) {
		pwarn("FAT length (%u sectors) insufficient for %u clusters "
		    "(minimum %ju sectors)\n",
		    chk->boot.fat_length, chk->boot.cluster_count,
		    (uintmax_t)min_fat_sectors);
		return (FSFATAL);
	}

	/* Cluster heap must fit within the volume (Spec §3.1.8 & §3.1.9) */
	heap_sectors = (uint64_t)chk->boot.cluster_count <<
	    chk->boot.cluster_shift;
	if ((uint64_t)chk->boot.cluster_heap_offset + heap_sectors >
	    chk->boot.volume_length) {
		pwarn("Cluster heap extends beyond volume length\n");
		return (FSFATAL);
	}

	/* Volume length must be at least 1MB in sectors (Spec §3.1.5) */
	if (chk->boot.volume_length <
	    (EXFAT_MIN_VOLUME_SIZE >> chk->boot.sector_shift)) {
		pwarn("Volume length (%ju sectors) too small "
		    "(minimum %ju sectors)\n",
		    (uintmax_t)chk->boot.volume_length,
		    (uintmax_t)(EXFAT_MIN_VOLUME_SIZE >>
		    chk->boot.sector_shift));
		return (FSFATAL);
	}

	/* Volume length must not exceed underlying media size */
	mediasize = 0;
	if ((ioctl(chk->fd, DIOCGMEDIASIZE, &mediasize) != 0 ||
	    mediasize == 0) &&
	    fstat(chk->fd, &sb) == 0 && S_ISREG(sb.st_mode))
		mediasize = sb.st_size;
	if (mediasize > 0 && chk->boot.volume_length >
	    ((uint64_t)mediasize >> chk->boot.sector_shift)) {
		pwarn("Volume length (%ju sectors) exceeds device "
		    "size (%ju sectors)\n",
		    (uintmax_t)chk->boot.volume_length,
		    (uintmax_t)((uint64_t)mediasize >>
		    chk->boot.sector_shift));
		return (FSFATAL);
	}

	if (!EXFAT_CLUSTER_VALID(chk, chk->boot.root_dir_cluster)) {
		pwarn("Invalid root directory cluster %u\n",
		    chk->boot.root_dir_cluster);
		return (FSFATAL);
	}

	/*
	 * Phase 3: Main Boot Region checksum calculation and verification.
	 *
	 * Compute 32-bit checksum over sectors 0 to 10 (Spec Section 3.4)
	 * and verify against the pattern recorded in sector 11.
	 */
	region = malloc(sec_size * EXFAT_BOOT_SECTORS_PER_REGION);
	csum_sec = malloc(sec_size);
	if (region == NULL || csum_sec == NULL) {
		perr("Out of memory allocating boot sector buffers");
		free(region);
		free(csum_sec);
		return (FSFATAL);
	}

	n = pread(chk->fd, region, sec_size * EXFAT_BOOT_SECTORS_CHECKSUM, 0);
	if (n != (ssize_t)(sec_size * EXFAT_BOOT_SECTORS_CHECKSUM)) {
		pwarn("Cannot read main boot region: %s\n", strerror(errno));
		main_ok = false;
	} else {
		if (vbr_sanitized)
			memcpy(region, &bs, sizeof(bs));
		main_csum = exfat_calc_boot_checksum(region, sec_size);
		n = pread(chk->fd, csum_sec, sec_size,
		    (off_t)EXFAT_BOOT_CHECKSUM_SECTOR * sec_size);
		if (n != (ssize_t)sec_size ||
		    !exfat_verify_boot_checksum_sector(csum_sec, sec_size,
		    main_csum) || vbr_sanitized) {
			if (!vbr_sanitized)
				pwarn("Main boot region checksum verification "
				    "failed\n");
			main_ok = false;
			mod |= FSERROR;
		}
	}

	/*
	 * Phase 4: Backup Boot Region checksum calculation and verification.
	 *
	 * Compute 32-bit checksum over backup sectors 12 to 22 (Spec Section
	 * 3.4) and verify against backup sector 23.
	 */
	n = pread(chk->fd, region, sec_size * EXFAT_BOOT_SECTORS_CHECKSUM,
	    (off_t)EXFAT_BACKUP_BOOT_SECTOR * sec_size);
	if (n != (ssize_t)(sec_size * EXFAT_BOOT_SECTORS_CHECKSUM)) {
		pwarn("Cannot read backup boot region: %s\n", strerror(errno));
		backup_ok = false;
	} else {
		backup_csum = exfat_calc_boot_checksum(region, sec_size);
		n = pread(chk->fd, csum_sec, sec_size,
		    (off_t)(EXFAT_BACKUP_BOOT_SECTOR +
		    EXFAT_BOOT_CHECKSUM_SECTOR) * sec_size);
		if (n != (ssize_t)sec_size ||
		    !exfat_verify_boot_checksum_sector(csum_sec, sec_size,
		    backup_csum) || vbr_sanitized) {
			if (!vbr_sanitized)
				pwarn("Backup boot region checksum "
				    "verification failed\n");
			backup_ok = false;
			mod |= FSERROR;
		}
	}

	/*
	 * Phase 5: Boot region repair and cross-synchronization.
	 *
	 * Restore corrupted regions per Spec Section 3.1 and 3.4:
	 * - If only one boot region is intact, restore the damaged region from
	 *   the intact counterpart.
	 * - If both checksums fail but geometry is valid, recompute the 32-bit
	 *   checksum and commit both regions.
	 * - If both are valid but mismatch, synchronize the backup from main.
	 */
	if (!main_ok && backup_ok) {
		if (ask(1, "Restore main boot region from backup")) {
			n = pread(chk->fd, region,
			    sec_size * EXFAT_BOOT_SECTORS_PER_REGION,
			    (off_t)EXFAT_BACKUP_BOOT_SECTOR * sec_size);
			if (n == (ssize_t)(sec_size *
			    EXFAT_BOOT_SECTORS_PER_REGION) &&
			    write_boot_region(chk->fd, region,
			    sec_size * EXFAT_BOOT_SECTORS_PER_REGION, 0)) {
				mod |= FSBOOTMOD;
				mod &= ~FSERROR;
			} else
				pwarn("Failed to restore main boot region: "
				    "%s\n", strerror(errno));
		}
	} else if (main_ok && !backup_ok) {
		if (ask(1, "Restore backup boot region from main")) {
			n = pread(chk->fd, region,
			    sec_size * EXFAT_BOOT_SECTORS_PER_REGION, 0);
			if (n == (ssize_t)(sec_size *
			    EXFAT_BOOT_SECTORS_PER_REGION) &&
			    write_boot_region(chk->fd, region,
			    sec_size * EXFAT_BOOT_SECTORS_PER_REGION,
			    (off_t)EXFAT_BACKUP_BOOT_SECTOR * sec_size)) {
				mod |= FSBOOTMOD;
				mod &= ~FSERROR;
			} else
				pwarn("Failed to restore backup boot region: "
				    "%s\n", strerror(errno));
		}
	} else if (!main_ok && !backup_ok) {
		if (ask(1, "Recompute and update boot checksums")) {
			off_t src_off = main_vbr_valid ? 0 :
			    (off_t)EXFAT_BACKUP_BOOT_SECTOR * sec_size;

			n = pread(chk->fd, region,
			    sec_size * EXFAT_BOOT_SECTORS_CHECKSUM, src_off);
			if (n == (ssize_t)(sec_size *
			    EXFAT_BOOT_SECTORS_CHECKSUM)) {
				if (vbr_sanitized || (mod & FSBOOTMOD) != 0)
					memcpy(region, &bs, sizeof(bs));
				main_csum = exfat_calc_boot_checksum(region,
				    sec_size);
				exfat_fill_boot_checksum_sector(csum_sec,
				    sec_size, main_csum);
				memcpy(region + sec_size *
				    EXFAT_BOOT_CHECKSUM_SECTOR, csum_sec,
				    sec_size);
				if (write_boot_region(chk->fd, region,
				    sec_size * EXFAT_BOOT_SECTORS_PER_REGION,
				    0) &&
				    write_boot_region(chk->fd, region,
				    sec_size * EXFAT_BOOT_SECTORS_PER_REGION,
				    (off_t)EXFAT_BACKUP_BOOT_SECTOR *
				    sec_size)) {
					mod |= FSBOOTMOD;
					mod &= ~FSERROR;
				} else
					pwarn("Failed to write boot region: "
					    "%s\n", strerror(errno));
			} else
				pwarn("Cannot read boot region: %s\n",
				    strerror(errno));
		}
	} else if (main_ok && backup_ok && main_csum != backup_csum) {
		pwarn("Backup boot region does not match main boot region\n");
		if (ask(1, "Synchronize backup boot region from main")) {
			n = pread(chk->fd, region,
			    sec_size * EXFAT_BOOT_SECTORS_PER_REGION, 0);
			if (n == (ssize_t)(sec_size *
			    EXFAT_BOOT_SECTORS_PER_REGION) &&
			    write_boot_region(chk->fd, region,
			    sec_size * EXFAT_BOOT_SECTORS_PER_REGION,
			    (off_t)EXFAT_BACKUP_BOOT_SECTOR * sec_size))
				mod |= FSBOOTMOD;
			else {
				pwarn("Failed to synchronize backup boot "
				    "region: %s\n", strerror(errno));
				mod |= FSERROR;
			}
		} else
			mod |= FSERROR;
	}

	free(region);
	free(csum_sec);

	/* Check volume cleanliness */
	if (chk->boot.volume_flags & EXFAT_VOL_DIRTY) {
		pwarn("Volume was not cleanly unmounted\n");
		mod |= FSDIRTY;
	}

	if (verbose) {
		printf("Volume Serial: 0x%08x\n", chk->boot.volume_serial);
		printf("FS Revision:   %u.%u\n",
		    chk->boot.fs_revision >> 8, chk->boot.fs_revision & 0xFF);
		printf("Sector Size:   %u bytes\n", chk->boot.sector_size);
		printf("Cluster Size:  %u bytes\n", chk->boot.cluster_size);
		printf("Total Clusters:%u\n", chk->boot.cluster_count);
		printf("Root Dir Clus: %u\n", chk->boot.root_dir_cluster);
	}

	return (mod);
}

/*
 * Clear EXFAT_VOL_DIRTY in both Main and Backup Boot Sectors.
 *
 * Updates VolumeFlags and PercentInUse in sector 0 and sector 12.
 * Recalculation of boot checksums is not required because VolumeFlags and
 * PercentInUse are excluded from the checksum per Spec §3.4.
 *
 * Returns FSBOOTMOD on success, FSFATAL on allocation failure, FSERROR on I/O
 * failure, or 0 if read-only.
 */
int
write_boot_clean(struct exfat_chk *chk)
{
	uint8_t *sec_buf;
	struct exfat_boot_sector *bs;
	off_t backup_offset;
	ssize_t n;
	size_t sec_size;

	if (rdonly)
		return (0);

	sec_size = chk->boot.sector_size;
	if (sec_size < sizeof(struct exfat_boot_sector))
		sec_size = sizeof(struct exfat_boot_sector);

	sec_buf = malloc(sec_size);
	if (sec_buf == NULL) {
		perr("Out of memory allocating boot sector buffer");
		return (FSFATAL);
	}

	/* Clear EXFAT_VOL_DIRTY in Main Boot Sector (sector 0) */
	n = pread(chk->fd, sec_buf, sec_size, 0);
	if (n != (ssize_t)sec_size) {
		pwarn("Cannot read main boot sector: %s\n", strerror(errno));
		free(sec_buf);
		return (FSERROR);
	}

	bs = (struct exfat_boot_sector *)sec_buf;
	chk->boot.volume_flags &= ~EXFAT_VOL_DIRTY;
	bs->bs_volume_flags = htole16(chk->boot.volume_flags);
	if (bs->bs_percent_in_use != EXFAT_PERCENT_IN_USE_UNKNOWN &&
	    chk->boot.cluster_count > 0) {
		uint32_t allocated;

		if (chk->clusters_free <= chk->boot.cluster_count)
			allocated = chk->boot.cluster_count -
			    chk->clusters_free;
		else
			allocated = 0;
		bs->bs_percent_in_use =
		    (uint8_t)(((uint64_t)allocated * 100) /
		    chk->boot.cluster_count);
		chk->boot.percent_in_use = bs->bs_percent_in_use;
	}
	n = pwrite(chk->fd, sec_buf, sec_size, 0);
	if (n != (ssize_t)sec_size) {
		pwarn("Cannot write main boot sector: %s\n", strerror(errno));
		free(sec_buf);
		return (FSERROR);
	}

	/* Clear EXFAT_VOL_DIRTY in Backup Boot Sector (sector 12) */
	backup_offset = (off_t)EXFAT_BACKUP_BOOT_SECTOR * chk->boot.sector_size;
	n = pread(chk->fd, sec_buf, sec_size, backup_offset);
	if (n != (ssize_t)sec_size) {
		pwarn("Cannot read backup boot sector: %s\n", strerror(errno));
		free(sec_buf);
		return (FSERROR);
	}

	bs = (struct exfat_boot_sector *)sec_buf;
	bs->bs_volume_flags = htole16(chk->boot.volume_flags);
	if (bs->bs_percent_in_use != EXFAT_PERCENT_IN_USE_UNKNOWN &&
	    chk->boot.cluster_count > 0)
		bs->bs_percent_in_use = chk->boot.percent_in_use;
	n = pwrite(chk->fd, sec_buf, sec_size, backup_offset);
	if (n != (ssize_t)sec_size) {
		pwarn("Cannot write backup boot sector: %s\n",
		    strerror(errno));
		free(sec_buf);
		return (FSERROR);
	}

	free(sec_buf);
	return (FSBOOTMOD);
}
