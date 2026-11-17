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
#include <sys/sysctl.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <fs/exfat/exfat_unicode.h>

#include "newfs_exfat.h"

/*
 * Format an exFAT filesystem according to the specified options.
 *
 * Determines sector and cluster geometry, computes partition size, formats
 * the Main Boot Region and Backup Boot Region with valid VBR, Extended Boot
 * sectors, OEM parameter sector, and Boot Checksum sector (Spec §3).
 * Allocates and initializes the File Allocation Table (FAT1), Allocation
 * Bitmap recording cluster allocations (Spec §7.1), loaded Up-case table
 * (Spec §7.2), and the initial Root Directory with optional Volume Label
 * (Spec §7.3).
 *
 * Returns 0 on success, or 1 on parameter validation or I/O failure.
 */
int
mkfs_exfat(const struct exfat_mkfs_opts *opts)
{
	struct stat sb;
	struct exfat_boot_sector *bs;
	struct exfat_dentry_bitmap *bm;
	struct exfat_dentry_upcase *uc;
	struct exfat_dentry_volume_label *vl;
	union exfat_dentry *dentry;
	uint8_t *vbr = NULL;
	uint8_t *bitmap_buf = NULL;
	uint8_t *upcase_buf = NULL;
	uint8_t *root_buf = NULL;
	uint32_t *fat = NULL;
	off_t volume_bytes = 0;
	off_t fat_byte_offset, fat_rem_bytes, bitmap_byte_offset;
	off_t root_byte_offset, upcase_byte_offset;
	uint64_t fat_bytes, total_clusters, total_sectors;
	uint32_t allocated_clusters, bitmap_clusters, bitmap_len;
	uint32_t boot_csum, cluster_count, cluster_heap_offset, cluster_size;
	uint32_t fat_length, fat_offset, root_dir_cluster;
	uint32_t sector_size, sectors_per_cluster, up_start, upcase_clusters;
	uint32_t volume_serial;
	uint8_t cluster_shift, sector_shift;
	size_t active_fat_bytes, bitmap_alloc_bytes, fat_chunk_bytes;
	size_t maxbuf_len, upcase_alloc_bytes, wr;
	size_t c, dent_idx, s;
	int fd = -1;
	int maxbuf, ret = 0;

	/*
	 * Phase 1: Volume geometry, sizing, and alignment calculations.
	 *
	 * Determine volume boundary, sector size/shift (Spec Section 3.1.14),
	 * cluster size/shift (Spec Section 3.1.15), and iteratively size the
	 * FAT (Spec Section 3.1.6 & 3.1.7). Align ClusterHeapOffset to cluster
	 * boundary (Spec Section 3.1.8), compute ClusterCount (Spec Section
	 * 3.1.9), and pre-allocate clusters for the Allocation Bitmap, Up-case
	 * Table, and Root Directory (Spec Section 3.1.10).
	 */
	if (opts->create_size > 0)
		volume_bytes = opts->create_size;
	else {
		fd = open(opts->special, opts->no_create ? O_RDONLY : O_RDWR);
		if (fd < 0) {
			warn("Cannot open '%s'", opts->special);
			return (1);
		}
		if (fstat(fd, &sb) != 0) {
			warn("Cannot stat '%s'", opts->special);
			close(fd);
			return (1);
		}
		if (S_ISREG(sb.st_mode))
			volume_bytes = sb.st_size;
		else if (S_ISCHR(sb.st_mode) || S_ISBLK(sb.st_mode)) {
			off_t mediasize;
			if (ioctl(fd, DIOCGMEDIASIZE, &mediasize) == 0)
				volume_bytes = mediasize;
		}
	}

	if (opts->volume_size > 0) {
		if (volume_bytes > 0 && opts->volume_size > volume_bytes) {
			warnx("Volume size exceeds target capacity");
			if (fd >= 0)
				close(fd);
			return (1);
		}
		volume_bytes = opts->volume_size;
	}

	if (volume_bytes < 1024 * 1024) {
		warnx("Volume size too small (must be at least 1 MiB)");
		if (fd >= 0)
			close(fd);
		return (1);
	}

	/* Determine sector size and shift */
	sector_size = opts->bytes_per_sector;
	if (sector_size == 0 && fd >= 0 &&
	    (S_ISCHR(sb.st_mode) || S_ISBLK(sb.st_mode))) {
		u_int dev_secsize;

		if (ioctl(fd, DIOCGSECTORSIZE, &dev_secsize) == 0 &&
		    dev_secsize > 0)
			sector_size = dev_secsize;
	}
	if (sector_size == 0)
		sector_size = 512;

	if (sector_size != 512 && sector_size != 1024 &&
	    sector_size != 2048 && sector_size != 4096) {
		warnx(
		    "Invalid sector size %u (must be 512, 1024, 2048, or 4096)",
		    sector_size);
		if (fd >= 0)
			close(fd);
		return (1);
	}

	if (fd >= 0 && (S_ISCHR(sb.st_mode) || S_ISBLK(sb.st_mode))) {
		u_int dev_secsize;

		if (ioctl(fd, DIOCGSECTORSIZE, &dev_secsize) == 0 &&
		    dev_secsize > 0 && sector_size < dev_secsize) {
			warnx("Sector size %u is smaller than device sector "
			    "size %u", sector_size, dev_secsize);
			close(fd);
			return (1);
		}
	}

	sector_shift = 0;
	while ((1U << sector_shift) < sector_size)
		sector_shift++;

	total_sectors = volume_bytes / sector_size;

	/* Determine cluster size and shift */
	maxbuf = 0;
	maxbuf_len = sizeof(maxbuf);

	if (sysctlbyname("vfs.maxbcachebuf", &maxbuf, &maxbuf_len, NULL,
	    0) != 0 || maxbuf < (int)sector_size)
		maxbuf = 64 * 1024;

	if (opts->cluster_size > 0) {
		if (opts->cluster_size <= 128)
			cluster_size = opts->cluster_size * sector_size;
		else
			cluster_size = opts->cluster_size;
		if (cluster_size > (uint32_t)maxbuf)
			warnx("Cluster size %u exceeds system maxbcachebuf "
			    "(%d); volume will fail to mount on standard "
			    "FreeBSD", cluster_size, maxbuf);
	} else if (volume_bytes < (off_t)32 * 1024 * 1024)
		cluster_size = 4096;
	else if (volume_bytes < (off_t)256 * 1024 * 1024)
		cluster_size = 4096;
	else if (volume_bytes < (off_t)32 * 1024 * 1024 * 1024)
		cluster_size = 32768;
	else {
		cluster_size = 131072;
		if (cluster_size > (uint32_t)maxbuf &&
		    powerof2(maxbuf) &&
		    (uint32_t)maxbuf >= sector_size)
			cluster_size = (uint32_t)maxbuf;
	}

	if (cluster_size < sector_size ||
	    cluster_size > EXFAT_MAX_CLUSTER_SIZE ||
	    !powerof2(cluster_size)) {
		warnx("Invalid cluster size %u (must be between %u and 32 MiB)",
		    cluster_size, sector_size);
		if (fd >= 0)
			close(fd);
		return (1);
	}

	cluster_shift = 0;
	while ((sector_size << cluster_shift) < cluster_size)
		cluster_shift++;

	sectors_per_cluster = 1U << cluster_shift;

	/* Calculate FAT offset, length, and cluster heap offset */
	fat_offset = EXFAT_MIN_FAT_OFFSET;

	/*
	 * Iterative sizing to fit cluster heap and FAT per
	 * Spec §3.1.6 through §3.1.9. Initial cluster count estimate to
	 * determine FAT length.
	 */
	total_clusters = (total_sectors - fat_offset) / sectors_per_cluster;
	if (total_clusters > EXFAT_MAX_CLUSTER_COUNT) {
		warnx("Too many clusters; increase cluster size");
		if (fd >= 0)
			close(fd);
		return (1);
	}
	cluster_count = (uint32_t)total_clusters;
	fat_bytes = ((uint64_t)cluster_count + 2) * sizeof(uint32_t);
	fat_length = (uint32_t)howmany(fat_bytes, sector_size);

	/*
	 * ClusterHeapOffset must be at least fat_offset + fat_length and should
	 * align to cluster boundary (Spec §3.1.8).
	 */
	cluster_heap_offset = fat_offset + fat_length;
	cluster_heap_offset = roundup(cluster_heap_offset, sectors_per_cluster);

	if (total_sectors <= cluster_heap_offset) {
		warnx("Volume too small for exFAT metadata structures");
		if (fd >= 0)
			close(fd);
		return (1);
	}

	/*
	 * Recompute exact ClusterCount and minimum FatLength given the aligned
	 * ClusterHeapOffset (Spec §3.1.7, §3.1.8, §3.1.9).
	 */
	total_clusters = (total_sectors - cluster_heap_offset) /
	    sectors_per_cluster;
	if (total_clusters < 1 || total_clusters > EXFAT_MAX_CLUSTER_COUNT) {
		warnx("Cluster count %ju out of valid range (1..%u) per "
		    "Spec §3.1.9", (uintmax_t)total_clusters,
		    EXFAT_MAX_CLUSTER_COUNT);
		if (fd >= 0)
			close(fd);
		return (1);
	}
	cluster_count = (uint32_t)total_clusters;
	fat_bytes = ((uint64_t)cluster_count + 2) * sizeof(uint32_t);
	fat_length = (uint32_t)howmany(fat_bytes, sector_size);

	/* System clusters allocation */
	bitmap_len = (uint32_t)howmany((uint64_t)cluster_count, 8);
	bitmap_clusters = (uint32_t)howmany((uint64_t)bitmap_len,
	    cluster_size);

	upcase_clusters = howmany(exfat_default_upcase_len, cluster_size);
	up_start = EXFAT_ITOCN(bitmap_clusters);

	root_dir_cluster = up_start + upcase_clusters;
	allocated_clusters = bitmap_clusters + upcase_clusters + 1;
	if (cluster_count < allocated_clusters) {
		warnx("Volume too small for exFAT metadata structures");
		if (fd >= 0)
			close(fd);
		return (1);
	}

	/* Volume serial number */
	if (opts->serial_set)
		volume_serial = opts->volume_serial;
	else
		volume_serial = arc4random();

	if (opts->verbose || opts->no_create) {
		printf("exFAT Format Parameters:\n");
		if (opts->volume_label != NULL && opts->volume_label[0] != '\0')
			printf("  Volume Label:       \"%s\"\n",
			    opts->volume_label);
		printf("  Volume Serial:      0x%08x\n", volume_serial);
		printf("  Volume Size:        %ju bytes (%ju sectors)\n",
		    (uintmax_t)volume_bytes, (uintmax_t)total_sectors);
		if (opts->partition_offset > 0)
			printf("  Partition Offset:   Sector %ju\n",
			    (uintmax_t)opts->partition_offset);
		printf("  Sector Size:        %u bytes\n", sector_size);
		printf("  Cluster Size:       %u bytes (%u sectors)\n",
		    cluster_size, sectors_per_cluster);
		printf("  FAT Offset:         Sector %u\n", fat_offset);
		printf("  FAT Length:         %u sectors\n", fat_length);
		printf("  Cluster Heap Offset:Sector %u\n",
		    cluster_heap_offset);
		printf("  Total Clusters:     %u\n", cluster_count);
		printf("  Root Dir Cluster:   %u\n", root_dir_cluster);
	}

	if (opts->no_create) {
		if (fd >= 0)
			close(fd);
		return (0);
	}

	if (opts->create_size > 0) {
		fd = open(opts->special, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			warn("Cannot create '%s'", opts->special);
			return (1);
		}
		if (ftruncate(fd, opts->create_size) != 0) {
			warn("Cannot set size of '%s'", opts->special);
			close(fd);
			return (1);
		}
	}

	/*
	 * Phase 2: Volume Boot Record synthesis and checksumming.
	 *
	 * Construct Main and Backup Boot Regions (12 sectors each):
	 * - Populate Main Boot Sector (VBR) parameters per Spec Section 3.1.
	 * - Initialize Extended Boot Sectors (1..8), OEM Parameters (9),
	 *   and Reserved Sector (10) with 0xAA55 signatures
	 *   (Spec §3.2 & §3.3).
	 * - Compute 32-bit boot checksum over sectors 0..10 and populate
	 *   sector 11 with the repeating checksum pattern (Spec Section 3.4).
	 * - Write both Main Boot Region (sector 0) and Backup Boot Region
	 *   (sector 12) to disk.
	 */
	vbr = calloc(EXFAT_BOOT_SECTORS_PER_REGION, sector_size);
	if (vbr == NULL) {
		warn("Out of memory allocating VBR buffer");
		ret = 1;
		goto out;
	}

	bs = (struct exfat_boot_sector *)vbr;

	/* Jump boot code (EB 76 90) */
	bs->bs_jmp_boot[0] = EXFAT_BOOT_JMP_0;
	bs->bs_jmp_boot[1] = EXFAT_BOOT_JMP_1;
	bs->bs_jmp_boot[2] = EXFAT_BOOT_JMP_2;

	memcpy(bs->bs_fs_name, EXFAT_FS_NAME, sizeof(bs->bs_fs_name));
	bs->bs_partition_offset = htole64(opts->partition_offset);
	bs->bs_volume_length = htole64(total_sectors);
	bs->bs_fat_offset = htole32(fat_offset);
	bs->bs_fat_length = htole32(fat_length);
	bs->bs_cluster_heap_offset = htole32(cluster_heap_offset);
	bs->bs_cluster_count = htole32(cluster_count);
	bs->bs_root_dir_cluster = htole32(root_dir_cluster);
	bs->bs_volume_serial = htole32(volume_serial);
	bs->bs_fs_revision = htole16(EXFAT_FS_REVISION);	/* 1.00 */
	bs->bs_volume_flags = htole16(0);	/* Clean */
	bs->bs_bytes_per_sector_shift = sector_shift;
	bs->bs_sectors_per_cluster_shift = cluster_shift;
	bs->bs_number_of_fats = 1;
	bs->bs_drive_select = EXFAT_DRIVE_SELECT_HD;
	bs->bs_percent_in_use = (uint8_t)(((uint64_t)allocated_clusters *
	    100) / cluster_count);
	bs->bs_boot_signature = htole16(EXFAT_BOOT_SIGNATURE);

	/* Extended boot sectors 1..8, OEM parameter 9, Reserved 10: 0xAA55 */
	for (s = 1; s < EXFAT_BOOT_CHECKSUM_SECTOR; s++) {
		uint8_t *sec = vbr + s * sector_size;
		le16enc(sec + sector_size - 2, EXFAT_BOOT_SIGNATURE);
	}

	/* Compute 32-bit boot checksum and populate sector 11 */
	boot_csum = exfat_calc_boot_checksum(vbr, sector_size);
	exfat_fill_boot_checksum_sector(vbr + EXFAT_BOOT_CHECKSUM_SECTOR *
	    sector_size, sector_size, boot_csum);

	/* Write Main Boot Region (sectors 0..11) */
	if (pwrite(fd, vbr, EXFAT_BOOT_SECTORS_PER_REGION * sector_size, 0) !=
	    (ssize_t)(EXFAT_BOOT_SECTORS_PER_REGION * sector_size)) {
		warn("Failed to write Main Boot Region");
		ret = 1;
		goto out;
	}

	/* Write Backup Boot Region (sectors 12..23) */
	if (pwrite(fd, vbr, EXFAT_BOOT_SECTORS_PER_REGION * sector_size,
	    (off_t)EXFAT_BACKUP_BOOT_SECTOR * sector_size) !=
	    (ssize_t)(EXFAT_BOOT_SECTORS_PER_REGION * sector_size)) {
		warn("Failed to write Backup Boot Region");
		ret = 1;
		goto out;
	}

	/*
	 * Phase 3: File Allocation Table (FAT) synthesis.
	 *
	 * Initialize media descriptor (entry 0) and reserved entry 1, link
	 * cluster chains for the Allocation Bitmap, Up-case Table, and Root
	 * Directory (terminating with EXFAT_FAT_EOF), and write active FAT
	 * sectors followed by zero-filled trailing sectors.
	 */
	active_fat_bytes = roundup((size_t)(root_dir_cluster + 1) *
	    sizeof(uint32_t), sector_size);
	fat_chunk_bytes = MAX(1024 * 1024, active_fat_bytes);
	if (fat_chunk_bytes > (size_t)fat_length * sector_size)
		fat_chunk_bytes = (size_t)fat_length * sector_size;

	fat = calloc(1, fat_chunk_bytes);
	if (fat == NULL) {
		warn("Out of memory allocating FAT buffer");
		ret = 1;
		goto out;
	}

	fat[0] = htole32(0xFFFFFFF8);	/* Media descriptor */
	fat[1] = htole32(0xFFFFFFFF);	/* Reserved */

	/* Bitmap cluster chain */
	for (c = 0; c < bitmap_clusters; c++) {
		uint32_t cn = EXFAT_ITOCN(c);
		if (c + 1 < bitmap_clusters)
			fat[cn] = htole32(cn + 1);
		else
			fat[cn] = htole32(EXFAT_FAT_EOF);
	}

	/* Up-case table cluster chain */
	for (c = 0; c < upcase_clusters; c++) {
		uint32_t cn = up_start + c;
		if (c + 1 < upcase_clusters)
			fat[cn] = htole32(cn + 1);
		else
			fat[cn] = htole32(EXFAT_FAT_EOF);
	}

	/* Root directory cluster */
	fat[root_dir_cluster] = htole32(EXFAT_FAT_EOF);

	fat_byte_offset = (off_t)fat_offset * sector_size;
	fat_rem_bytes = (off_t)fat_length * sector_size;

	wr = MIN((size_t)fat_rem_bytes, fat_chunk_bytes);
	if (pwrite(fd, fat, wr, fat_byte_offset) != (ssize_t)wr) {
		warn("Failed to write FAT table");
		ret = 1;
		goto out;
	}
	fat_byte_offset += wr;
	fat_rem_bytes -= wr;

	if (fat_rem_bytes > 0) {
		memset(fat, 0, fat_chunk_bytes);
		while (fat_rem_bytes > 0) {
			wr = MIN((size_t)fat_rem_bytes, fat_chunk_bytes);
			if (pwrite(fd, fat, wr, fat_byte_offset) !=
			    (ssize_t)wr) {
				warn("Failed to write FAT table");
				ret = 1;
				goto out;
			}
			fat_byte_offset += wr;
			fat_rem_bytes -= wr;
		}
	}

	/*
	 * Phase 4: Allocation Bitmap initialization.
	 *
	 * Allocate bitmap buffer and mark initial system clusters (Allocation
	 * Bitmap, Up-case Table, and Root Directory) as allocated in the bitmap
	 * (Spec Section 7.1). Write the bitmap to disk at ClusterHeapOffset.
	 */
	bitmap_alloc_bytes = (size_t)bitmap_clusters * cluster_size;
	bitmap_buf = calloc(1, bitmap_alloc_bytes);
	if (bitmap_buf == NULL) {
		warn("Out of memory allocating bitmap buffer");
		ret = 1;
		goto out;
	}

	/* Mark allocated clusters (0 .. allocated_clusters - 1) */
	for (c = 0; c < allocated_clusters; c++)
		bitmap_buf[c / 8] |= (1U << (c % 8));

	bitmap_byte_offset = (off_t)cluster_heap_offset * sector_size;
	if (pwrite(fd, bitmap_buf, bitmap_alloc_bytes, bitmap_byte_offset) !=
	    (ssize_t)bitmap_alloc_bytes) {
		warn("Failed to write Allocation Bitmap");
		ret = 1;
		goto out;
	}

	/*
	 * Phase 5: Up-Case Table generation.
	 *
	 * Allocate buffer, copy compressed default up-case table data (Spec
	 * Section 7.2), and write to disk at the allocated cluster offset.
	 */
	upcase_alloc_bytes = (size_t)upcase_clusters * cluster_size;
	upcase_buf = calloc(1, upcase_alloc_bytes);
	if (upcase_buf == NULL) {
		warn("Out of memory allocating upcase buffer");
		ret = 1;
		goto out;
	}
	memcpy(upcase_buf, exfat_default_upcase, exfat_default_upcase_len);

	upcase_byte_offset = (off_t)exfat_cluster_to_sector(
	    cluster_heap_offset, cluster_shift, up_start) * sector_size;

	if (pwrite(fd, upcase_buf, upcase_alloc_bytes, upcase_byte_offset) !=
	    (ssize_t)upcase_alloc_bytes) {
		warn("Failed to write Up-Case Table");
		ret = 1;
		goto out;
	}

	/*
	 * Phase 6: Root Directory initialization.
	 *
	 * Allocate root directory buffer and populate directory entries:
	 * - Volume Label Entry if label provided (Spec Section 7.3).
	 * - Allocation Bitmap Directory Entry pointing to cluster 2 (Spec
	 *   Section 7.1).
	 * - Up-Case Table Directory Entry pointing to up_start with table
	 *   checksum (Spec Section 7.2).
	 * - End of Directory (EOD) marker (0x00).
	 * Write Root Directory cluster to disk and flush via fsync().
	 */
	root_buf = calloc(1, cluster_size);
	if (root_buf == NULL) {
		warn("Out of memory allocating root directory buffer");
		ret = 1;
		goto out;
	}

	dentry = (union exfat_dentry *)root_buf;
	dent_idx = 0;

	/* Volume Label Entry (0x83) */
	if (opts->volume_label != NULL && opts->volume_label[0] != '\0') {
		uint16_t label_utf16[EXFAT_MAX_LABEL_CHARS];
		size_t nchars = 0;
		int error;

		error = exfat_utf8_to_utf16(opts->volume_label,
		    strlen(opts->volume_label), label_utf16,
		    EXFAT_MAX_LABEL_CHARS, &nchars);
		if (error == 0 && nchars > 0) {
			vl = &dentry[dent_idx++].volume_label;
			vl->vl_type = EXFAT_ENTRY_VOLUME_LABEL;
			vl->vl_character_count = (uint8_t)nchars;
			for (size_t i = 0; i < nchars; i++)
				vl->vl_volume_label[i] =
				    htole16(label_utf16[i]);
		}
	}

	/* Allocation Bitmap Entry (0x81) */
	bm = &dentry[dent_idx++].bitmap;
	bm->bm_type = EXFAT_ENTRY_BITMAP;
	bm->bm_flags = 0;
	bm->bm_first_cluster = htole32(EXFAT_FIRST_CLUSTER);
	bm->bm_data_length = htole64(bitmap_len);

	/* Up-Case Table Entry (0x82) */
	uc = &dentry[dent_idx++].upcase;
	uc->uc_type = EXFAT_ENTRY_UPCASE;
	uc->uc_table_checksum = htole32(exfat_default_upcase_checksum);
	uc->uc_first_cluster = htole32(up_start);
	uc->uc_data_length = htole64(exfat_default_upcase_len);

	/* End of Directory Entry (0x00) */
	dentry[dent_idx].type = EXFAT_ENTRY_EOD;

	root_byte_offset = (off_t)exfat_cluster_to_sector(cluster_heap_offset,
	    cluster_shift, root_dir_cluster) * sector_size;

	if (pwrite(fd, root_buf, cluster_size, root_byte_offset) !=
	    (ssize_t)cluster_size) {
		warn("Failed to write Root Directory");
		ret = 1;
		goto out;
	}

	fsync(fd);

out:
	free(vbr);
	free(fat);
	free(bitmap_buf);
	free(upcase_buf);
	free(root_buf);
	if (fd >= 0)
		close(fd);
	return (ret);
}
