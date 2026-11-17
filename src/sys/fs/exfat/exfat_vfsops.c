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
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/endian.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/lockmgr.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/module.h>
#include <sys/namei.h>
#include <sys/priv.h>
#include <sys/stat.h>
#include <sys/vnode.h>

#include <geom/geom.h>
#include <geom/geom_vfs.h>

#include <fs/exfat/exfat_fat.h>
#include <fs/exfat/exfat_lookup.h>
#include <fs/exfat/exfat_node.h>
#include <fs/exfat/exfat_ondisk.h>
#include <fs/exfat/exfat_unicode.h>
#include <fs/exfat/exfat_vfsops.h>

#if __FreeBSD_version < 1600026
/*
 * Close a GEOM consumer with the GEOM topology lock held.
 *
 * Compatibility helper for FreeBSD versions prior to 1600026 where
 * g_vfs_close() required callers to hold the GEOM topology lock.
 */
static inline void
g_vfs_close_unlocked(struct g_consumer *cp)
{
	g_topology_lock();
	g_vfs_close(cp);
	g_topology_unlock();
}
#endif

MALLOC_DEFINE(M_EXFATMNT, "exfat_mount", "EXFAT mount structure");

static vfs_sync_t	exfat_sync;
static vfs_unmount_t	exfat_unmount;

/*
 * Validate an on-disk Volume Boot Record (VBR) per Specification §3.1.
 *
 * Verifies the 0xAA55 boot signature, jump boot instruction, "EXFAT   " file
 * system name, zeroed fields, sector shift (512B–4096B), cluster shift (up to
 * 32MB clusters), FAT count (1 or 2 for TexFAT), major file system revision,
 * FAT length, cluster heap boundaries, root directory cluster range, and
 * volume length bounds.
 *
 * Returns 0 if the boot sector parameters are valid, EINVAL otherwise.
 */
static int
exfat_validate_vbr(const struct exfat_boot_sector *bs)
{
	uint64_t heap_sectors, min_fat_sectors, volume_length;
	uint32_t cluster_count, cluster_heap_offset, fat_length, fat_offset;
	uint32_t root_dir_cluster, sector_size;
	size_t i;

	if (le16toh(bs->bs_boot_signature) != EXFAT_BOOT_SIGNATURE)
		return (EINVAL);

	/* Jump instruction must be 0xEB 0x76 0x90 per Spec §3.1.1 */
	if (bs->bs_jmp_boot[0] != EXFAT_BOOT_JMP_0 ||
	    bs->bs_jmp_boot[1] != EXFAT_BOOT_JMP_1 ||
	    bs->bs_jmp_boot[2] != EXFAT_BOOT_JMP_2)
		return (EINVAL);

	if (memcmp(bs->bs_fs_name, EXFAT_FS_NAME, sizeof(bs->bs_fs_name)) != 0)
		return (EINVAL);

	for (i = 0; i < sizeof(bs->bs_must_be_zero); i++)
		if (bs->bs_must_be_zero[i] != 0)
			return (EINVAL);

	/* Sector size power of 2: 9 (512B) to 12 (4096B) */
	if (bs->bs_bytes_per_sector_shift < EXFAT_MIN_SECTOR_SHIFT ||
	    bs->bs_bytes_per_sector_shift > EXFAT_MAX_SECTOR_SHIFT)
		return (EINVAL);

	/* Cluster size power of 2: maximum cluster size is 32MB (25) */
	if (bs->bs_bytes_per_sector_shift + bs->bs_sectors_per_cluster_shift >
	    EXFAT_MAX_CLUSTER_SHIFT)
		return (EINVAL);

	/* Number of FATs must be 1 or 2 (TexFAT) */
	if (bs->bs_number_of_fats != 1 && bs->bs_number_of_fats != 2)
		return (EINVAL);

	/* ActiveFat is only valid when NumberOfFats is 2 (Spec §3.1.13.1) */
	if (bs->bs_number_of_fats == 1 &&
	    (le16toh(bs->bs_volume_flags) & EXFAT_VOL_ACTIVE_FAT) != 0)
		return (EINVAL);

	/*
	 * ClearToZero requires clearing the entire volume to zero or
	 * reformatting before mounting per Spec §3.1.13.4.
	 */
	if ((le16toh(bs->bs_volume_flags) & EXFAT_VOL_CLEAR_TO_ZERO) != 0)
		return (EINVAL);

	/* Major revision must be 1 per Spec §3.1.12 */
	if ((le16toh(bs->bs_fs_revision) >> 8) != EXFAT_FS_REVISION_MAJOR)
		return (EINVAL);

	fat_offset = le32toh(bs->bs_fat_offset);
	fat_length = le32toh(bs->bs_fat_length);
	cluster_heap_offset = le32toh(bs->bs_cluster_heap_offset);
	cluster_count = le32toh(bs->bs_cluster_count);
	root_dir_cluster = le32toh(bs->bs_root_dir_cluster);
	volume_length = le64toh(bs->bs_volume_length);
	sector_size = 1U << bs->bs_bytes_per_sector_shift;

	/*
	 * First FAT offset must be at or after Main + Backup boot sectors
	 * (24 sectors).
	 */
	if (fat_offset < EXFAT_MIN_FAT_OFFSET)
		return (EINVAL);

	/* Cluster heap offset must be at or after the FAT tables */
	if (cluster_heap_offset < fat_offset +
	    (uint64_t)bs->bs_number_of_fats * fat_length)
		return (EINVAL);

	/* Cluster count must be between 1 and EXFAT_MAX_CLUSTER_COUNT */
	if (cluster_count < 1 ||
	    cluster_count > EXFAT_MAX_CLUSTER_COUNT)
		return (EINVAL);

	/* Root directory cluster must be within the cluster heap */
	if (!exfat_cluster_is_valid(root_dir_cluster, cluster_count))
		return (EINVAL);

	/* Volume length must be at least 1MB in sectors (Spec §3.1.5) */
	if (volume_length < (EXFAT_MIN_VOLUME_SIZE >>
	    bs->bs_bytes_per_sector_shift))
		return (EINVAL);

	/* Cluster heap must not extend beyond the volume */
	heap_sectors = (uint64_t)cluster_count <<
	    bs->bs_sectors_per_cluster_shift;
	if ((uint64_t)cluster_heap_offset + heap_sectors > volume_length)
		return (EINVAL);

	/* FAT length must be sufficient to cover all clusters */
	min_fat_sectors = howmany((uint64_t)(cluster_count + 2) *
	    sizeof(uint32_t), sector_size);
	if (fat_length < min_fat_sectors)
		return (EINVAL);

	/* PercentInUse must be 0-100 or 0xFF (Spec §3.1.18) */
	if (bs->bs_percent_in_use > 100 &&
	    bs->bs_percent_in_use != EXFAT_PERCENT_IN_USE_UNKNOWN)
		return (EINVAL);

	return (0);
}

/*
 * Validate the 32-bit Boot Region Checksum per exFAT Specification §3.4.
 *
 * Computes a rolling checksum over the 11 sectors of the boot region starting
 * at start_sector (excluding VolumeFlags and PercentInUse in sector 0 per
 * specification rules).  Compares the result against the repeating 32-bit
 * checksum pattern in the Boot Checksum Sector (sector start_sector + 11).
 *
 * Returns 0 if the checksum matches, EINVAL on mismatch, or an I/O error.
 */
static int
exfat_validate_boot_checksum(struct vnode *devvp, uint32_t start_sector,
    uint8_t sector_shift)
{
	struct buf *bp;
	const uint8_t *cdata, *data;
	daddr_t csum_daddr, daddr;
	size_t sector_size;
	uint32_t checksum;
	int error;

	sector_size = 1U << sector_shift;
	checksum = 0;

	for (uint32_t s = 0; s < EXFAT_BOOT_SECTORS_CHECKSUM; s++) {
		daddr = (daddr_t)(start_sector + s) <<
		    (sector_shift - DEV_BSHIFT);
		error = bread(devvp, daddr, sector_size, NOCRED, &bp);
		if (error != 0) {
			if (bp != NULL)
				brelse(bp);
			return (error);
		}

		data = (const uint8_t *)bp->b_data;
		checksum = exfat_boot_sector_checksum(data, sector_size,
		    checksum, (s == 0));

		bp->b_flags |= B_INVAL | B_RELBUF | B_NOCACHE;
		bp->b_flags &= ~(B_ASYNC | B_CACHE);
		brelse(bp);
	}

	/* Read Boot Checksum Sector (sector 11 of the region) */
	csum_daddr = (daddr_t)(start_sector + EXFAT_BOOT_CHECKSUM_SECTOR) <<
	    (sector_shift - DEV_BSHIFT);
	error = bread(devvp, csum_daddr, sector_size, NOCRED, &bp);
	if (error != 0) {
		if (bp != NULL)
			brelse(bp);
		return (error);
	}

	cdata = (const uint8_t *)bp->b_data;
	if (!exfat_verify_boot_checksum_sector(cdata, sector_size, checksum)) {
		bp->b_flags |= B_INVAL | B_RELBUF | B_NOCACHE;
		bp->b_flags &= ~(B_ASYNC | B_CACHE);
		brelse(bp);
		return (EINVAL);
	}

	bp->b_flags |= B_INVAL | B_RELBUF | B_NOCACHE;
	bp->b_flags &= ~(B_ASYNC | B_CACHE);
	brelse(bp);
	return (0);
}

/*
 * Read and validate a Boot Region (Main or Backup) starting at start_sector.
 *
 * Issues a bread() for the boot sector at daddr of bsize bytes, validates
 * the VBR fields via exfat_validate_vbr(), copies the valid VBR into
 * pmp->pm_vbr, and validates the entire 12-sector boot region checksum with
 * exfat_validate_boot_checksum().  If expected_shift is non-zero, verifies
 * that the sector shift matches expected_shift.
 *
 * Returns 0 on success, EINVAL if parameters or checksums are invalid, or
 * an I/O error from bread().
 */
static int
exfat_read_boot_region(struct vnode *devvp, struct exfat_mount *pmp,
    uint32_t start_sector, daddr_t daddr, int bsize, uint8_t expected_shift)
{
	struct buf *bp;
	struct exfat_boot_sector *bs;
	uint8_t shift;
	int error;

	bp = NULL;
	error = bread(devvp, daddr, bsize, NOCRED, &bp);
	if (error != 0) {
		if (bp != NULL)
			brelse(bp);
		return (error);
	}

	bs = (struct exfat_boot_sector *)bp->b_data;
	error = exfat_validate_vbr(bs);
	if (error != 0) {
		bp->b_flags |= B_INVAL | B_RELBUF | B_NOCACHE;
		bp->b_flags &= ~(B_ASYNC | B_CACHE);
		brelse(bp);
		return (error);
	}

	shift = bs->bs_bytes_per_sector_shift;
	if (expected_shift != 0 && shift != expected_shift) {
		bp->b_flags |= B_INVAL | B_RELBUF | B_NOCACHE;
		bp->b_flags &= ~(B_ASYNC | B_CACHE);
		brelse(bp);
		return (EINVAL);
	}
	if ((1U << shift) < (size_t)bsize) {
		bp->b_flags |= B_INVAL | B_RELBUF | B_NOCACHE;
		bp->b_flags &= ~(B_ASYNC | B_CACHE);
		brelse(bp);
		return (EINVAL);
	}

	memcpy(&pmp->pm_vbr, bs, sizeof(pmp->pm_vbr));
	bp->b_flags |= B_INVAL | B_RELBUF | B_NOCACHE;
	bp->b_flags &= ~(B_ASYNC | B_CACHE);
	brelse(bp);

	return (exfat_validate_boot_checksum(devvp, start_sector, shift));
}

/*
 * Read and parse the Volume Boot Record from the underlying device.
 *
 * First attempts to read the Main Boot Region (Sector 0) via
 * exfat_read_boot_region().  If the Main Boot Region is corrupted or fails
 * checksum validation, falls back to probing the Backup Boot Region
 * (Sector 12) across possible sector shifts (512B to 4096B).  If the backup
 * succeeds, the volume is mounted read-only and marked dirty.  Precalculates
 * volume geometry, shifts, masks, and cluster sizes in pmp.
 *
 * Returns 0 on success, or an error code if both boot regions are invalid or
 * unreadable.
 */
static int
exfat_read_vbr(struct vnode *devvp, struct exfat_mount *pmp)
{
	int error, secsize;
	uint8_t shift;

	secsize = DEV_BSIZE;
	if (pmp->pm_cp != NULL && pmp->pm_cp->provider != NULL) {
		if (pmp->pm_cp->provider->sectorsize < DEV_BSIZE ||
		    pmp->pm_cp->provider->sectorsize >
		    (1U << EXFAT_MAX_SECTOR_SHIFT))
			return (EINVAL);
		secsize = pmp->pm_cp->provider->sectorsize;
	}

	/*
	 * Attempt to read Main Boot Sector (Sector 0).
	 */
	error = exfat_read_boot_region(devvp, pmp, 0, 0, secsize, 0);
	if (error != 0) {
		/*
		 * If Main VBR or its boot region checksum is corrupted or
		 * unreadable, attempt reading the Backup Boot Sector
		 * (Sector 12) across valid sector shifts (512B to 4096B).
		 */
		for (shift = EXFAT_MIN_SECTOR_SHIFT;
		    shift <= EXFAT_MAX_SECTOR_SHIFT; shift++) {
			daddr_t daddr;
			int bsize = 1 << shift;

			if (bsize < secsize)
				continue;
			daddr = (daddr_t)EXFAT_BACKUP_BOOT_SECTOR <<
			    (shift - DEV_BSHIFT);
			error = exfat_read_boot_region(devvp, pmp,
			    EXFAT_BACKUP_BOOT_SECTOR, daddr, bsize, shift);
			if (error == 0)
				break;
		}
		if (error != 0)
			return (error);
		/*
		 * Main Boot Sector is damaged; force read-only mount and
		 * mark the in-memory volume flags dirty so RW remount is
		 * refused until repaired by fsck_exfat.
		 */
		pmp->pm_vbr.bs_volume_flags |= htole16(EXFAT_VOL_DIRTY);
		pmp->pm_flags |= EXFAT_MNT_RONLY;
	}

	/* Precalculate shifts, masks, and sizes */
	pmp->pm_sector_shift = pmp->pm_vbr.bs_bytes_per_sector_shift;
	pmp->pm_cluster_shift = pmp->pm_vbr.bs_sectors_per_cluster_shift;
	pmp->pm_sector_size = 1U << pmp->pm_sector_shift;
	pmp->pm_cluster_size = pmp->pm_sector_size << pmp->pm_cluster_shift;
	pmp->pm_cluster_mask = pmp->pm_cluster_size - 1;

	/*
	 * Ensure cluster size does not exceed the buffer cache maximum block
	 * size (maxbcachebuf).
	 */
	if (pmp->pm_cluster_size > maxbcachebuf)
		return (EINVAL);

	pmp->pm_volume_length = le64toh(pmp->pm_vbr.bs_volume_length);
	pmp->pm_fat_offset = le32toh(pmp->pm_vbr.bs_fat_offset);
	pmp->pm_fat_length = le32toh(pmp->pm_vbr.bs_fat_length);
	pmp->pm_cluster_heap_offset =
	    le32toh(pmp->pm_vbr.bs_cluster_heap_offset);
	pmp->pm_cluster_count = le32toh(pmp->pm_vbr.bs_cluster_count);
	pmp->pm_rootdir_cluster = le32toh(pmp->pm_vbr.bs_root_dir_cluster);

	if (pmp->pm_cp != NULL && pmp->pm_cp->provider != NULL) {
		if (pmp->pm_sector_size < pmp->pm_cp->provider->sectorsize)
			return (EINVAL);
		if (pmp->pm_volume_length >
		    ((uint64_t)pmp->pm_cp->provider->mediasize >>
		    pmp->pm_sector_shift))
			return (EINVAL);
	}

	if (le16toh(pmp->pm_vbr.bs_volume_flags) & EXFAT_VOL_DIRTY)
		pmp->pm_flags |= EXFAT_MNT_RONLY;

	return (0);
}

/*
 * Set or clear the VolumeDirty flag in the Main Boot Sector (Sector 0).
 *
 * Reads sector 0 synchronously.  If dirty is true, sets EXFAT_VOL_DIRTY in
 * VolumeFlags to indicate active read-write mounting.  If dirty is false,
 * clears EXFAT_VOL_DIRTY and updates PercentInUse (Spec §3.1.18) to reflect
 * the percentage of allocated clusters on clean unmount.  Commits changes
 * synchronously with bwrite().
 *
 * Returns 0 on success (or if mounted read-only), or an I/O error from
 * buffer read/write.
 */
static int
exfat_mark_voldirty(struct exfat_mount *pmp, bool dirty)
{
	struct exfat_boot_sector *bs;
	struct buf *bp;
	uint16_t flags;
	int error;

	if ((pmp->pm_flags & EXFAT_MNT_RONLY) != 0)
		return (0);

	error = bread(pmp->pm_devvp, 0, pmp->pm_sector_size, NOCRED, &bp);
	if (error != 0) {
		if (bp != NULL)
			brelse(bp);
		return (error);
	}

	bs = (struct exfat_boot_sector *)bp->b_data;
	flags = le16toh(pmp->pm_vbr.bs_volume_flags);
	if (dirty)
		flags |= EXFAT_VOL_DIRTY;
	else {
		flags &= ~EXFAT_VOL_DIRTY;
		/*
		 * Microsoft exFAT Specification §3.1.18 (PercentInUse Field):
		 * An exFAT implementation may update this field upon cleanly
		 * unmounting the volume. If percentage is unknown or
		 * unavailable, it contains 0xFF. If tracked (!= 0xFF), update
		 * to the rounded down integer percentage of allocated clusters.
		 */
		if (bs->bs_percent_in_use != EXFAT_PERCENT_IN_USE_UNKNOWN &&
		    pmp->pm_cluster_count > 0) {
			uint32_t allocated;

			if (pmp->pm_free_clusters <= pmp->pm_cluster_count)
				allocated = pmp->pm_cluster_count -
				    pmp->pm_free_clusters;
			else
				allocated = 0;
			bs->bs_percent_in_use =
			    (uint8_t)(((uint64_t)allocated * 100) /
			    pmp->pm_cluster_count);
			pmp->pm_vbr.bs_percent_in_use = bs->bs_percent_in_use;
		}
	}

	bs->bs_volume_flags = htole16(flags);
	pmp->pm_vbr.bs_volume_flags = htole16(flags);

	bp->b_flags |= B_INVALONERR;
	return (bwrite(bp));
}

/*
 * Synchronize clean state to the Backup Boot Sector (Sector 12).
 *
 * Reads Sector 12 synchronously, clears EXFAT_VOL_DIRTY in VolumeFlags,
 * updates PercentInUse to match the Main Boot Sector, and commits the
 * buffer synchronously with bwrite().
 *
 * Returns 0 on success (or if mounted read-only), or an I/O error.
 */
static int
exfat_sync_backup_vbr(struct exfat_mount *pmp)
{
	struct exfat_boot_sector *bs;
	struct buf *bp;
	daddr_t daddr;
	uint16_t flags;
	int error;

	if ((pmp->pm_flags & EXFAT_MNT_RONLY) != 0)
		return (0);

	daddr = (daddr_t)EXFAT_BACKUP_BOOT_SECTOR <<
	    (pmp->pm_sector_shift - DEV_BSHIFT);
	error = bread(pmp->pm_devvp, daddr, pmp->pm_sector_size, NOCRED, &bp);
	if (error != 0) {
		if (bp != NULL)
			brelse(bp);
		return (error);
	}

	bs = (struct exfat_boot_sector *)bp->b_data;
	flags = le16toh(pmp->pm_vbr.bs_volume_flags);
	flags &= ~EXFAT_VOL_DIRTY;
	bs->bs_volume_flags = htole16(flags);
	if (bs->bs_percent_in_use != EXFAT_PERCENT_IN_USE_UNKNOWN &&
	    pmp->pm_cluster_count > 0)
		bs->bs_percent_in_use = pmp->pm_vbr.bs_percent_in_use;

	bp->b_flags |= B_INVALONERR;
	return (bwrite(bp));
}

/*
 * Load and decompress the Up-case table from disk into memory.
 *
 * Reads the cluster chain of the Up-case table entry starting at
 * pmp->pm_upcase_cluster, validates its 32-bit checksum against
 * pmp->pm_upcase_checksum per Specification §7.2.2, and decompresses the
 * table into a flat 128 KiB array of 65,536 entries via
 * exfat_decompress_upcase(), storing the table in pmp->pm_upcase.
 *
 * Returns 0 on success, EINVAL on invalid parameters or checksum mismatch,
 * or an I/O error from cluster reads.
 */
static int
exfat_load_upcase(struct exfat_mount *pmp)
{
	uint8_t *raw_buf;
	uint16_t *table;
	uint32_t checksum, cn;
	uint64_t bytes_remaining;
	size_t offset;
	int error;

	if (!EXFAT_CLUSTER_VALID(pmp, pmp->pm_upcase_cluster) ||
	    pmp->pm_upcase_length == 0 ||
	    (pmp->pm_upcase_length & 1) != 0 ||
	    pmp->pm_upcase_length > EXFAT_MAX_UPCASE_SIZE)
		return (EINVAL);

	raw_buf = malloc(pmp->pm_upcase_length, M_TEMP, M_WAITOK);
	bytes_remaining = pmp->pm_upcase_length;
	offset = 0;
	cn = pmp->pm_upcase_cluster;

	while (bytes_remaining > 0) {
		struct buf *bp;
		size_t to_copy;

		error = exfat_read_cluster(pmp, cn, &bp);
		if (error != 0) {
			free(raw_buf, M_TEMP);
			return (error);
		}

		to_copy = pmp->pm_cluster_size;
		if (bytes_remaining < to_copy)
			to_copy = (size_t)bytes_remaining;

		memcpy(raw_buf + offset, bp->b_data, to_copy);
		bp->b_flags |= B_INVAL | B_RELBUF | B_NOCACHE;
		bp->b_flags &= ~(B_ASYNC | B_CACHE);
		brelse(bp);

		bytes_remaining -= to_copy;
		offset += to_copy;

		if (bytes_remaining > 0) {
			uint32_t next_cn;

			error = exfat_fat_get(pmp, cn, &next_cn);
			if (error != 0) {
				free(raw_buf, M_TEMP);
				return (error);
			}
			if (!EXFAT_CLUSTER_VALID(pmp, next_cn)) {
				free(raw_buf, M_TEMP);
				return (EIO);
			}
			cn = next_cn;
		}
	}

	/* Validate checksum */
	checksum = exfat_boot_checksum(raw_buf, pmp->pm_upcase_length, 0);
	if (checksum != pmp->pm_upcase_checksum) {
		printf("exfat: up-case table checksum mismatch: "
		    "computed 0x%08x != expected 0x%08x\n",
		    checksum, pmp->pm_upcase_checksum);
		free(raw_buf, M_TEMP);
		return (EINVAL);
	}

	/* Allocate flat in-memory table (65,536 * 2 bytes = 128 KiB) */
	table = malloc(EXFAT_UPCASE_TABLE_CHARS * sizeof(uint16_t), M_EXFATMNT,
	    M_WAITOK);
	error = exfat_decompress_upcase(raw_buf, pmp->pm_upcase_length, table);
	free(raw_buf, M_TEMP);
	if (error != 0) {
		printf("exfat: malformed up-case table data\n");
		free(table, M_EXFATMNT);
		return (error);
	}

	pmp->pm_upcase = table;
	return (0);
}

/*
 * Load the cluster Allocation Bitmap from disk into memory.
 *
 * Reads the cluster chain starting at pmp->pm_bitmap_cluster for
 * pmp->pm_bitmap_length bytes into pmp->pm_bitmap.  Counts free (0) bits to
 * initialize pmp->pm_free_clusters and sets the initial allocation rotor
 * cursor pmp->pm_last_allocated_cluster.
 *
 * Returns 0 on success, EINVAL if bitmap bounds are invalid, or an I/O
 * error from cluster reads.
 */
static int
exfat_load_bitmap(struct exfat_mount *pmp)
{
	uint8_t *bitmap;
	uint32_t cn, free_clusters;
	uint64_t bytes_remaining;
	size_t offset;
	int error;

	if (!EXFAT_CLUSTER_VALID(pmp, pmp->pm_bitmap_cluster) ||
	    pmp->pm_bitmap_length <
	    howmany((uint64_t)pmp->pm_cluster_count, 8) ||
	    (uint64_t)pmp->pm_cluster_count >
	    (uint64_t)pmp->pm_bitmap_length * 8 ||
	    pmp->pm_bitmap_length > EXFAT_MAX_BITMAP_SIZE)
		return (EINVAL);

	bitmap = malloc(pmp->pm_bitmap_length, M_EXFATMNT, M_WAITOK);
	bytes_remaining = pmp->pm_bitmap_length;
	offset = 0;
	cn = pmp->pm_bitmap_cluster;

	while (bytes_remaining > 0) {
		struct buf *bp;
		size_t to_copy;

		error = exfat_read_cluster(pmp, cn, &bp);
		if (error != 0) {
			free(bitmap, M_EXFATMNT);
			return (error);
		}

		to_copy = pmp->pm_cluster_size;
		if (bytes_remaining < to_copy)
			to_copy = (size_t)bytes_remaining;

		memcpy(bitmap + offset, bp->b_data, to_copy);
		bp->b_flags |= B_INVAL | B_RELBUF | B_NOCACHE;
		bp->b_flags &= ~(B_ASYNC | B_CACHE);
		brelse(bp);

		bytes_remaining -= to_copy;
		offset += to_copy;

		if (bytes_remaining > 0) {
			uint32_t next_cn;

			error = exfat_fat_get(pmp, cn, &next_cn);
			if (error != 0) {
				free(bitmap, M_EXFATMNT);
				return (error);
			}
			if (!EXFAT_CLUSTER_VALID(pmp, next_cn)) {
				free(bitmap, M_EXFATMNT);
				return (EIO);
			}
			cn = next_cn;
		}
	}

	free_clusters = 0;
	for (uint32_t i = 0; i < pmp->pm_cluster_count; i++)
		if ((bitmap[i / 8] & (1U << (i % 8))) == 0)
			free_clusters++;
	pmp->pm_free_clusters = free_clusters;
	pmp->pm_last_allocated_cluster = EXFAT_FIRST_CLUSTER;
	pmp->pm_bitmap = bitmap;
	return (0);
}

/*
 * Scan the Root Directory to locate and load critical system metadata.
 *
 * Traverses root directory entries (Spec §3.1.10) to discover:
 * 1. Allocation Bitmap (0x81) matching the active FAT (Spec §3.1.13.1, §7.1).
 * 2. Up-case Table (0x82) locator and checksum (Spec §7.2).
 * 3. Volume Label (0x83) UTF-16 string (Spec §7.3).
 *
 * Once located, calls exfat_load_upcase() and exfat_load_bitmap() to load
 * and initialize in-memory tables.
 *
 * Returns 0 on success, EINVAL if required critical entries are missing or
 * corrupt, ELOOP on cyclic directory loops, or an I/O error.
 */
static int
exfat_scan_rootdir(struct exfat_mount *pmp)
{
	uint32_t cn;
	uint32_t loop_count = 0;
	bool active_fat_is_second;
	bool found_bitmap = false;
	bool found_label = false;
	bool found_upcase = false;
	int error;

	active_fat_is_second = (pmp->pm_vbr.bs_number_of_fats > 1) &&
	    ((le16toh(pmp->pm_vbr.bs_volume_flags) &
	    EXFAT_VOL_ACTIVE_FAT) != 0);

	/*
	 * Phase 1: Scan root directory entries for critical system metadata.
	 *
	 * Traverse the root directory cluster chain (Spec Section 3.1.10) to
	 * locate the Allocation Bitmap matching the active FAT (Spec Section
	 * 3.1.13.1 & 7.1.2), the Up-case Table (Spec Section 7.2), and the
	 * Volume Label (Spec Section 7.3).
	 */
	cn = pmp->pm_rootdir_cluster;
	while (EXFAT_CLUSTER_VALID(pmp, cn)) {
		struct buf *bp;
		const union exfat_dentry *dent;
		size_t num_entries;
		size_t i;
		bool stop_scan = false;

		if (++loop_count > pmp->pm_cluster_count)
			return (ELOOP);

		error = exfat_read_cluster(pmp, cn, &bp);
		if (error != 0)
			return (error);

		dent = (const union exfat_dentry *)bp->b_data;
		num_entries = pmp->pm_cluster_size / sizeof(union exfat_dentry);

		for (i = 0; i < num_entries; i++) {
			uint8_t type = dent[i].type;

			if (type == EXFAT_ENTRY_EOD) {
				stop_scan = true;
				break;
			}
			if ((type & EXFAT_ENTRY_TYPE_IN_USE) == 0)
				continue;

			switch (type) {
			case EXFAT_ENTRY_BITMAP:
				/*
				 * Match bitmap to active FAT per Spec
				 * §3.1.13.1 & §7.1.2.
				 */
				if (((dent[i].bitmap.bm_flags &
				    EXFAT_BITMAP_FLAG_SECOND) != 0) ==
				    active_fat_is_second && !found_bitmap) {
					pmp->pm_bitmap_cluster = le32toh(
					    dent[i].bitmap.bm_first_cluster);
					pmp->pm_bitmap_length = le64toh(
					    dent[i].bitmap.bm_data_length);
					found_bitmap = true;
				}
				break;
			case EXFAT_ENTRY_UPCASE:
				if (!found_upcase) {
					pmp->pm_upcase_checksum = le32toh(
					    dent[i].upcase.uc_table_checksum);
					pmp->pm_upcase_cluster = le32toh(
					    dent[i].upcase.uc_first_cluster);
					pmp->pm_upcase_length = le64toh(
					    dent[i].upcase.uc_data_length);
					found_upcase = true;
				}
				break;
			case EXFAT_ENTRY_VOLUME_LABEL:
				if (!found_label &&
				    dent[i].volume_label.vl_character_count <=
				    EXFAT_MAX_VOLUME_LABEL_CHARS) {
					uint16_t label_utf16[
					    EXFAT_MAX_VOLUME_LABEL_CHARS];
					uint8_t nchars = dent[i].volume_label.
					    vl_character_count;

					for (uint8_t k = 0; k < nchars; k++)
						label_utf16[k] = le16toh(
						    dent[i].volume_label.
						    vl_volume_label[k]);
					if (exfat_is_valid_label(label_utf16,
					    nchars)) {
						exfat_utf16_to_utf8(label_utf16,
						    nchars, pmp->pm_vollabel,
						    sizeof(pmp->pm_vollabel));
						found_label = true;
					}
				}
				break;
			case EXFAT_ENTRY_FILE:
			case EXFAT_ENTRY_STREAM:
			case EXFAT_ENTRY_NAME:
			case EXFAT_ENTRY_VOLUME_GUID:
			case EXFAT_ENTRY_TEXFAT_PADDING:
			case EXFAT_ENTRY_VENDOR_EXT:
			case EXFAT_ENTRY_VENDOR_ALLOC:
				/*
				 * Recognized primary and secondary entries that
				 * do not require root metadata extraction.
				 */
				break;
			default:
				/*
				 * Per exFAT Spec §6.2.1, unrecognized critical
				 * directory entries (TypeImportance == 0) must
				 * be considered an error and reject mounting.
				 * Benign entries (TypeImportance == 1) may be
				 * safely ignored.
				 */
				if ((type & EXFAT_ENTRY_TYPE_BENIGN) == 0) {
					printf("exfat: unrecognized critical "
					    "directory entry 0x%02x\n", type);
					brelse(bp);
					return (EINVAL);
				}
				break;
			}
		}

		brelse(bp);

		if (stop_scan)
			break;

		/* Follow FAT chain to next root directory cluster */
		error = exfat_fat_get(pmp, cn, &cn);
		if (error != 0)
			return (error);
	}

	if (!found_bitmap || !found_upcase) {
		printf("exfat: missing critical root directory entries "
		    "(bitmap=%d, upcase=%d)\n", found_bitmap, found_upcase);
		return (EINVAL);
	}

	/*
	 * Phase 2: Load and decompress up-case table.
	 *
	 * Read and decompress the up-case table mapping into memory (Spec
	 * Section 7.2).
	 */
	error = exfat_load_upcase(pmp);
	if (error != 0)
		return (error);

	/*
	 * Phase 3: Load cluster allocation bitmap.
	 *
	 * Read the cluster allocation bitmap into memory (Spec Section 7.1).
	 */
	return (exfat_load_bitmap(pmp));
}

/*
 * Common mount initialization routine for an exFAT volume.
 *
 * Allocates struct exfat_mount, initializes locks and permission masks, reads
 * and validates the VBR via exfat_read_vbr(), bootstraps metadata from the
 * root directory via exfat_scan_rootdir(), marks the volume dirty with
 * exfat_mark_voldirty() if mounted read-write, and registers the mount with
 * the FreeBSD VFS layer without advertising shared vnode locks.
 *
 * Returns 0 on success, or an error code from boot sector validation or
 * root directory bootstrap.
 */
static int
exfat_mountfs(struct vnode *devvp, struct mount *mp, struct g_consumer *cp)
{
	struct exfat_mount *pmp;
	int error;

	/*
	 * Phase 1: Allocate in-memory mount structure and initialize locks.
	 */
	pmp = malloc(sizeof(*pmp), M_EXFATMNT, M_WAITOK | M_ZERO);
	pmp->pm_mountp = mp;
	pmp->pm_devvp = devvp;
	pmp->pm_cp = cp;
	pmp->pm_bo = &devvp->v_bufobj;
	pmp->pm_dev = devvp->v_rdev;
	pmp->pm_uid = 0;
	pmp->pm_gid = 0;
	pmp->pm_mask = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	pmp->pm_dirmask = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

	if ((mp->mnt_flag & MNT_RDONLY) != 0)
		pmp->pm_flags |= EXFAT_MNT_RONLY;

	lockinit(&pmp->pm_lock, 0, "exfatlk", 0, LK_CANRECURSE);

	/*
	 * Phase 2: Read and validate the Volume Boot Record (VBR).
	 *
	 * Parse Main Boot Region sectors (Spec Section 3.1) and verify
	 * volume parameters and boot checksums.
	 */
	error = exfat_read_vbr(devvp, pmp);
	if (error != 0) {
		lockdestroy(&pmp->pm_lock);
		free(pmp, M_EXFATMNT);
		return (error);
	}

	if (pmp->pm_vbr.bs_number_of_fats > 1 &&
	    (pmp->pm_flags & EXFAT_MNT_RONLY) == 0) {
		printf("exfat: TexFAT (dual-FAT) write support unavailable; "
		    "mounting read-only\n");
		pmp->pm_flags |= EXFAT_MNT_RONLY;
	}

	/*
	 * Phase 3: Bootstrap filesystem metadata from the root directory.
	 *
	 * Scan the root directory to locate the active Allocation Bitmap
	 * (Spec Section 7.1) and Up-case Table (Spec Section 7.2), and load
	 * them into memory.
	 */
	error = exfat_scan_rootdir(pmp);
	if (error != 0) {
		if (pmp->pm_upcase != NULL)
			free(pmp->pm_upcase, M_EXFATMNT);
		if (pmp->pm_bitmap != NULL)
			free(pmp->pm_bitmap, M_EXFATMNT);
		lockdestroy(&pmp->pm_lock);
		free(pmp, M_EXFATMNT);
		return (error);
	}

	/*
	 * Phase 4: Mark volume dirty for write mounts.
	 *
	 * Set VolumeDirty in VolumeFlags (Spec Section 3.1.13.2) to detect
	 * unclean unmounts on subsequent boots.
	 */
	if ((pmp->pm_flags & EXFAT_MNT_RONLY) == 0) {
		error = exfat_mark_voldirty(pmp, true);
		if (error != 0) {
			if (pmp->pm_upcase != NULL)
				free(pmp->pm_upcase, M_EXFATMNT);
			if (pmp->pm_bitmap != NULL)
				free(pmp->pm_bitmap, M_EXFATMNT);
			lockdestroy(&pmp->pm_lock);
			free(pmp, M_EXFATMNT);
			return (error);
		}
	} else if ((mp->mnt_flag & MNT_RDONLY) == 0 && cp != NULL) {
		g_topology_lock();
		(void)g_access(cp, 0, -1, 0);
		g_topology_unlock();
	}

	/*
	 * Phase 5: Register mount instance with FreeBSD VFS layer.
	 */
	mp->mnt_data = pmp;
	MNT_ILOCK(mp);
	mp->mnt_flag |= MNT_LOCAL;
	if ((pmp->pm_flags & EXFAT_MNT_RONLY) != 0)
		mp->mnt_flag |= MNT_RDONLY;
	/*
	 * Do not set MNTK_LOOKUP_SHARED or MNTK_EXTENDED_SHARED: exfat vnodes
	 * do not opt into shared locking (VN_LOCK_ASHARE) and mutate per-node
	 * cache/state under the vnode lock without a separate internal lock.
	 * Match msdosfs.
	 *
	 * MNTK_FPLOOKUP enables lockless fast-path namecache lookup
	 * (cache_fplookup).  exFAT supports this via exfat_fplookup_vexec()
	 * with static mount permissions and SMR-synchronized node reclamation.
	 */
	mp->mnt_kern_flag |= MNTK_USES_BCACHE | MNTK_NO_IOPF | MNTK_FPLOOKUP;
	MNT_IUNLOCK(mp);

	return (0);
}

static const char *exfat_opts[] = {
	"from", "export", "ro", "sync", "async", "noatime", "force",
	"noclusterr", "noclusterw", "uid", "gid", "mask", "dirmask",
	"trim", "notrim",
	NULL
};

static int
exfat_cmount(struct mntarg *ma, void *data, uint64_t flags)
{
	struct exfat_args args;
	int error;

	if (data == NULL)
		return (EINVAL);
	error = copyin(data, &args, sizeof(args));
	if (error != 0)
		return (error);

	ma = mount_argsu(ma, "from", args.fspec, MAXPATHLEN);
	ma = mount_arg(ma, "export", &args.export, sizeof(args.export));
	ma = mount_argf(ma, "uid", "%d", args.uid);
	ma = mount_argf(ma, "gid", "%d", args.gid);
	ma = mount_argf(ma, "mask", "%d", args.mask);
	ma = mount_argf(ma, "dirmask", "%d", args.dirmask);

	ma = mount_argb(ma, args.flags & EXFAT_MNT_TRIM, "notrim");

	return (kernel_mount(ma, flags));
}

static int
exfat_mount(struct mount *mp)
{
	struct vnode *devvp;
	struct thread *td;
	struct cdev *dev;
	struct g_consumer *cp;
	struct exfat_mount *pmp = NULL;
	struct nameidata ndp;
	int error, val;
	accmode_t accmode;
	char *from;

	td = curthread;

	if (vfs_filteropt(mp->mnt_optnew, exfat_opts))
		return (EINVAL);

	if (mp->mnt_flag & MNT_UPDATE) {
		pmp = VFSTOEXFAT(mp);
		if (pmp == NULL)
			return (EINVAL);

		/*
		 * Note on MNT_RDONLY asymmetry during MNT_UPDATE:
		 * Before invoking VFS_MOUNT(mp), vfs_domount_update() clears
		 * MNT_UPDATEMASK from mp->mnt_flag and then ORs in
		 * (fsflags & (... | MNT_RDONLY)).  Because MNT_RDONLY is not
		 * in MNT_UPDATEMASK:
		 * - On RW -> RO downgrade, mp->mnt_flag starts with MNT_RDONLY
		 *   clear and vfs_domount_update() sets MNT_RDONLY if requested
		 *   via either mount flags or the "ro" option, so testing
		 *   (mp->mnt_flag & MNT_RDONLY) != 0 here catches flag-only
		 *   callers in addition to "ro" in mnt_optnew.
		 * - On RO -> RW upgrade, mp->mnt_flag still has MNT_RDONLY set
		 *   on entry to VFS_MOUNT(mp) and is only cleared below once
		 *   the upgrade succeeds, so RO -> RW must test mnt_optnew
		 *   rather than mp->mnt_flag.
		 */
		if (!(pmp->pm_flags & EXFAT_MNT_RONLY) &&
		    ((mp->mnt_flag & MNT_RDONLY) != 0 ||
		    vfs_flagopt(mp->mnt_optnew, "ro", NULL, 0))) {
			int flags = WRITECLOSE;

			error = vn_start_write(NULL, &mp, V_WAIT | V_PCATCH);
			if (error != 0)
				return (error);
			error = vfs_write_suspend_umnt(mp);
			if (error != 0) {
				vn_finished_write(mp);
				return (error);
			}

			if (mp->mnt_flag & MNT_FORCE)
				flags |= FORCECLOSE;
			error = exfat_sync(mp, MNT_WAIT);
			if (error != 0) {
				vfs_write_resume(mp, 0);
				return (error);
			}
			error = vflush(mp, 0, flags, td);
			if (error != 0) {
				vfs_write_resume(mp, 0);
				return (error);
			}

			if (pmp->pm_devvp != NULL) {
				vn_lock(pmp->pm_devvp, LK_EXCLUSIVE | LK_RETRY);
				error = VOP_FSYNC(pmp->pm_devvp, MNT_WAIT, td);
				VOP_UNLOCK(pmp->pm_devvp);
				if (error != 0) {
					vfs_write_resume(mp, 0);
					return (error);
				}
			}
			error = exfat_mark_voldirty(pmp, false);
			if (error != 0) {
				(void)exfat_mark_voldirty(pmp, true);
				vfs_write_resume(mp, 0);
				return (error);
			}
			error = exfat_sync_backup_vbr(pmp);
			if (error != 0) {
				(void)exfat_mark_voldirty(pmp, true);
				vfs_write_resume(mp, 0);
				return (error);
			}
			if (pmp->pm_devvp != NULL) {
				vn_lock(pmp->pm_devvp, LK_EXCLUSIVE | LK_RETRY);
				error = VOP_FSYNC(pmp->pm_devvp, MNT_WAIT, td);
				VOP_UNLOCK(pmp->pm_devvp);
				if (error != 0) {
					(void)exfat_mark_voldirty(pmp, true);
					vfs_write_resume(mp, 0);
					return (error);
				}
			}

			g_topology_lock();
			error = g_access(pmp->pm_cp, 0, -1, 0);
			g_topology_unlock();
			if (error != 0) {
				(void)exfat_mark_voldirty(pmp, true);
				vfs_write_resume(mp, 0);
				return (error);
			}

			pmp->pm_flags |= EXFAT_MNT_RONLY;
			MNT_ILOCK(mp);
			mp->mnt_flag |= MNT_RDONLY;
			MNT_IUNLOCK(mp);
			vfs_write_resume(mp, 0);
		} else if ((pmp->pm_flags & EXFAT_MNT_RONLY) &&
		    !vfs_flagopt(mp->mnt_optnew, "ro", NULL, 0)) {
			if (pmp->pm_vbr.bs_number_of_fats > 1)
				return (EROFS);

			if (le16toh(pmp->pm_vbr.bs_volume_flags) &
			    EXFAT_VOL_DIRTY)
				return (EROFS);

			vn_lock(pmp->pm_devvp, LK_EXCLUSIVE | LK_RETRY);
			error = VOP_ACCESS(pmp->pm_devvp, VREAD | VWRITE,
			    td->td_ucred, td);
			if (error != 0)
				error = priv_check(td, PRIV_VFS_MOUNT_PERM);
			if (error != 0) {
				VOP_UNLOCK(pmp->pm_devvp);
				return (error);
			}
			VOP_UNLOCK(pmp->pm_devvp);

			g_topology_lock();
			error = g_access(pmp->pm_cp, 0, 1, 0);
			g_topology_unlock();
			if (error != 0)
				return (error);

			pmp->pm_flags &= ~EXFAT_MNT_RONLY;
			error = exfat_mark_voldirty(pmp, true);
			if (error != 0) {
				g_topology_lock();
				(void)g_access(pmp->pm_cp, 0, -1, 0);
				g_topology_unlock();
				pmp->pm_flags |= EXFAT_MNT_RONLY;
				return (error);
			}

			MNT_ILOCK(mp);
			mp->mnt_flag &= ~MNT_RDONLY;
			MNT_IUNLOCK(mp);
		}

		if (vfs_scanopt(mp->mnt_optnew, "gid", "%i", &val) == 1)
			pmp->pm_gid = val;
		if (vfs_scanopt(mp->mnt_optnew, "uid", "%i", &val) == 1)
			pmp->pm_uid = val;
		if (vfs_scanopt(mp->mnt_optnew, "mask", "%i", &val) == 1)
			pmp->pm_mask = val & ALLPERMS;
		if (vfs_scanopt(mp->mnt_optnew, "dirmask", "%i", &val) == 1)
			pmp->pm_dirmask = val & ALLPERMS;
		if (vfs_getopt(mp->mnt_optnew, "trim", NULL, NULL) == 0)
			pmp->pm_flags |= EXFAT_MNT_TRIM;
		else if (vfs_getopt(mp->mnt_optnew, "notrim", NULL, NULL) == 0)
			pmp->pm_flags &= ~EXFAT_MNT_TRIM;
		return (0);
	}

	/*
	 * Look up the block device to mount.
	 */
	if (vfs_getopt(mp->mnt_optnew, "from", (void **)&from, NULL))
		return (EINVAL);

	NDINIT(&ndp, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, from);
	error = namei(&ndp);
	if (error != 0)
		return (error);
	devvp = ndp.ni_vp;
	NDFREE_PNBUF(&ndp);

	if (!vn_isdisk_error(devvp, &error)) {
		vput(devvp);
		return (error);
	}

	accmode = (mp->mnt_flag & MNT_RDONLY) ? VREAD : (VREAD | VWRITE);
	error = VOP_ACCESS(devvp, accmode, td->td_ucred, td);
	if (error != 0)
		error = priv_check(td, PRIV_VFS_MOUNT_PERM);
	if (error != 0) {
		vput(devvp);
		return (error);
	}

	dev = devvp->v_rdev;
	dev_ref(dev);
	g_topology_lock();
	error = g_vfs_open(devvp, &cp, "exfat",
	    (mp->mnt_flag & MNT_RDONLY) ? 0 : 1);
	g_topology_unlock();
	VOP_UNLOCK(devvp);
	if (error != 0) {
		dev_rel(dev);
		vrele(devvp);
		return (error);
	}

	if (dev->si_iosize_max != 0)
		mp->mnt_iosize_max = dev->si_iosize_max;
	if ((u_long)mp->mnt_iosize_max > maxphys)
		mp->mnt_iosize_max = maxphys;

	error = exfat_mountfs(devvp, mp, cp);
	if (error != 0) {
		g_vfs_close_unlocked(cp);
		dev_rel(dev);
		vrele(devvp);
		return (error);
	}

	pmp = VFSTOEXFAT(mp);

	mp->mnt_stat.f_fsid.val[0] = dev2udev(dev);
	mp->mnt_stat.f_fsid.val[1] = mp->mnt_vfc->vfc_typenum;

	/* Parse user-supplied ownership and permission overrides */
	if (vfs_scanopt(mp->mnt_optnew, "gid", "%i", &val) == 1)
		pmp->pm_gid = val;
	if (vfs_scanopt(mp->mnt_optnew, "uid", "%i", &val) == 1)
		pmp->pm_uid = val;
	if (vfs_scanopt(mp->mnt_optnew, "mask", "%i", &val) == 1)
		pmp->pm_mask = val & ALLPERMS;
	if (vfs_scanopt(mp->mnt_optnew, "dirmask", "%i", &val) == 1)
		pmp->pm_dirmask = val & ALLPERMS;
	if (vfs_getopt(mp->mnt_optnew, "trim", NULL, NULL) == 0)
		pmp->pm_flags |= EXFAT_MNT_TRIM;

	vfs_mountedfrom(mp, from);
	return (0);
}

static int
exfat_unmount(struct mount *mp, int mntflags)
{
	struct exfat_mount *pmp;
	int error, flags, sync_error = 0;
	bool susp;

	pmp = VFSTOEXFAT(mp);
	if (pmp == NULL)
		return (0);

	susp = (pmp->pm_flags & EXFAT_MNT_RONLY) == 0;
	if (susp) {
		error = vfs_write_suspend_umnt(mp);
		if (error != 0)
			return (error);
	}

	flags = 0;
	if ((mntflags & MNT_FORCE) != 0) {
		if (mp->mnt_flag & MNT_ROOTFS) {
			if (susp)
				vfs_write_resume(mp, VR_START_WRITE);
			return (EINVAL);
		}
		flags |= FORCECLOSE;
	}

	if (susp && (mntflags & MNT_FORCE) == 0)
		sync_error = exfat_sync(mp, MNT_WAIT);

	error = vflush(mp, 0, flags, curthread);
	if (error != 0 && (error != ENXIO || (mntflags & MNT_FORCE) == 0)) {
		if (susp)
			vfs_write_resume(mp, VR_START_WRITE);
		return (error);
	}

	if (susp && error == 0 && sync_error == 0) {
		if (pmp->pm_devvp != NULL) {
			vn_lock(pmp->pm_devvp, LK_EXCLUSIVE | LK_RETRY);
			sync_error = VOP_FSYNC(pmp->pm_devvp, MNT_WAIT,
			    curthread);
			VOP_UNLOCK(pmp->pm_devvp);
		}
		if (sync_error == 0) {
			(void)exfat_mark_voldirty(pmp, false);
			(void)exfat_sync_backup_vbr(pmp);
			if (pmp->pm_devvp != NULL) {
				vn_lock(pmp->pm_devvp,
				    LK_EXCLUSIVE | LK_RETRY);
				(void)VOP_FSYNC(pmp->pm_devvp, MNT_WAIT,
				    curthread);
				VOP_UNLOCK(pmp->pm_devvp);
			}
		}
	}
	if (susp)
		vfs_write_resume(mp, VR_START_WRITE);

	if (pmp->pm_cp != NULL)
		g_vfs_close_unlocked(pmp->pm_cp);
	if (pmp->pm_devvp != NULL)
		vrele(pmp->pm_devvp);
	if (pmp->pm_dev != NULL)
		dev_rel(pmp->pm_dev);

	if (pmp->pm_upcase != NULL)
		free(pmp->pm_upcase, M_EXFATMNT);
	if (pmp->pm_bitmap != NULL)
		free(pmp->pm_bitmap, M_EXFATMNT);

	lockdestroy(&pmp->pm_lock);
	free(pmp, M_EXFATMNT);
	mp->mnt_data = NULL;
	return (0);
}

static int
exfat_root(struct mount *mp, int flags, struct vnode **vpp)
{
	struct exfat_mount *pmp;
	struct exfat_node *np;
	int error;

	pmp = VFSTOEXFAT(mp);
	if (pmp == NULL)
		return (EINVAL);

	/*
	 * Exfat vnodes do not opt into shared locking; enforce exclusive
	 * root vnode lock.
	 */
	error = exfat_node_get(pmp, EXFAT_ROOT_DIRCLUST, EXFAT_ROOT_DIROFFSET,
	    (flags & ~LK_TYPE_MASK) | LK_EXCLUSIVE, &np);
	if (error != 0)
		return (error);

	*vpp = NODETOV(np);
	return (0);
}

static int
exfat_statfs(struct mount *mp, struct statfs *sbp)
{
	struct exfat_mount *pmp;

	pmp = VFSTOEXFAT(mp);
	if (pmp == NULL)
		return (0);

	/*
	 * Provide an advisory snapshot of filesystem capacity and free
	 * clusters without acquiring pm_lock, avoiding serialization against
	 * concurrent cluster allocations or metadata flush operations.
	 */
	sbp->f_bsize = pmp->pm_cluster_size;
	sbp->f_iosize = pmp->pm_cluster_size;
	sbp->f_blocks = pmp->pm_cluster_count;
	sbp->f_bfree = pmp->pm_free_clusters;
	sbp->f_bavail = pmp->pm_free_clusters;
	sbp->f_files = pmp->pm_cluster_count;
	sbp->f_ffree = pmp->pm_free_clusters;

	return (0);
}

static int
exfat_sync(struct mount *mp, int waitfor)
{
	struct vnode *vp, *mvp;
	struct thread *td;
	struct exfat_node *np;
	struct exfat_mount *pmp;
	int error, allerror = 0, lkflags;

	pmp = VFSTOEXFAT(mp);
	if (pmp == NULL)
		return (0);

	if ((pmp->pm_flags & EXFAT_MNT_RONLY) != 0)
		return (0);

	td = curthread;

loop:
	MNT_VNODE_FOREACH_ALL(vp, mp, mvp) {
		if (vp->v_type == VNON) {
			VI_UNLOCK(vp);
			continue;
		}
		np = VTONODE(vp);
		if (np == NULL) {
			VI_UNLOCK(vp);
			continue;
		}
		if ((np->node_flag & (EXFAT_NODE_MTIME | EXFAT_NODE_ATIME |
		    EXFAT_NODE_DIRTY)) == 0 &&
		    (vp->v_bufobj.bo_dirty.bv_cnt == 0 ||
		    waitfor == MNT_LAZY)) {
			VI_UNLOCK(vp);
			continue;
		}
		lkflags = LK_EXCLUSIVE | LK_INTERLOCK;
		if (waitfor != MNT_WAIT && waitfor != MNT_SUSPEND)
			lkflags |= LK_NOWAIT;
		error = vget(vp, lkflags);
		if (error != 0) {
			if (error == ENOENT) {
				MNT_VNODE_FOREACH_ALL_ABORT(mp, mvp);
				goto loop;
			}
			continue;
		}
		error = VOP_FSYNC(vp, waitfor, td);
		if (error != 0)
			allerror = error;
		vput(vp);
	}

	/*
	 * Flush filesystem control info and backing device buffers
	 * (FAT & bitmap).
	 */
	if (waitfor != MNT_LAZY && pmp->pm_devvp != NULL) {
		vn_lock(pmp->pm_devvp, LK_EXCLUSIVE | LK_RETRY);
		error = VOP_FSYNC(pmp->pm_devvp, waitfor, td);
		if (error != 0)
			allerror = error;
		VOP_UNLOCK(pmp->pm_devvp);
	}

	if (allerror == 0 && waitfor == MNT_SUSPEND) {
		MNT_ILOCK(mp);
		mp->mnt_kern_flag |= MNTK_SUSPEND2 | MNTK_SUSPENDED;
		MNT_IUNLOCK(mp);
	}
	return (allerror);
}

static int
exfat_fhtovp(struct mount *mp, struct fid *fhp, int flags, struct vnode **vpp)
{
	struct exfat_mount *pmp;
	struct exfat_fid *fid;
	struct exfat_node *np;
	int error;

	pmp = VFSTOEXFAT(mp);
	if (pmp == NULL) {
		*vpp = NULL;
		return (EINVAL);
	}
	fid = (struct exfat_fid *)fhp;
	if (fid->fid_len < sizeof(struct exfat_fid)) {
		*vpp = NULL;
		return (EINVAL);
	}

	/*
	 * Validate directory entry cluster and offset bounds.
	 * Per exFAT Spec §6.3 and §7.4, directory entry sets may straddle
	 * directory cluster boundaries. The primary directory entry may begin
	 * at the final 32-byte slot of a cluster
	 * (fid_dirofs = cluster_size - 32) while subsequent entries continue in
	 * the next cluster. Therefore, only verify that fid_dirofs does not
	 * exceed cluster bounds (dirofs < cluster_size and 32-byte aligned),
	 * matching exfat_node_load(). Verify that fid_dirclust is allocated in
	 * the allocation bitmap (Spec §7.1) to reject stale file handles.
	 */
	if (!EXFAT_IS_ROOT(fid->fid_dirclust, fid->fid_dirofs) &&
	    (!EXFAT_CLUSTER_VALID(pmp, fid->fid_dirclust) ||
	    !exfat_bitmap_is_cluster_allocated(pmp, fid->fid_dirclust) ||
	    (fid->fid_dirofs % sizeof(union exfat_dentry)) != 0 ||
	    fid->fid_dirofs >= pmp->pm_cluster_size)) {
		*vpp = NULL;
		return (ESTALE);
	}

	/*
	 * Exfat vnodes do not opt into shared locking; enforce exclusive
	 * lock when looking up vnode by filehandle.
	 */
	error = exfat_node_get(pmp, fid->fid_dirclust, fid->fid_dirofs,
	    (flags & ~LK_TYPE_MASK) | LK_EXCLUSIVE, &np);
	if (error != 0) {
		*vpp = NULL;
		return (error);
	}

	if ((np->node_flag & EXFAT_NODE_UNLINKED) != 0) {
		vput(NODETOV(np));
		*vpp = NULL;
		return (ESTALE);
	}

	*vpp = NODETOV(np);
	vnode_create_vobject(*vpp, np->node_size, curthread);
	return (0);
}

struct vfsops exfat_vfsops = {
	.vfs_cmount	= exfat_cmount,
	.vfs_fhtovp	= exfat_fhtovp,
	.vfs_mount	= exfat_mount,
	.vfs_root	= exfat_root,
	.vfs_statfs	= exfat_statfs,
	.vfs_sync	= exfat_sync,
	.vfs_unmount	= exfat_unmount,
};

VFS_SET(exfat_vfsops, exfat, 0);
MODULE_VERSION(exfat, 1);
