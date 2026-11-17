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
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/vnode.h>

#include <geom/geom.h>

#include <fs/exfat/exfat_fat.h>
#include <fs/exfat/exfat_ondisk.h>
#include <fs/exfat/exfat_vfsops.h>

/*
 * Convert a cluster number cn (cn >= EXFAT_FIRST_CLUSTER) to a disk block
 * address in DEV_BSIZE (512-byte) units.
 *
 * Translates cluster cn within the cluster heap using pm_cluster_heap_offset
 * and pm_cluster_shift, and scales to DEV_BSIZE blocks.
 *
 * Returns the device block address (daddr_t).
 */
daddr_t
exfat_cntodaddr(struct exfat_mount *pmp, uint32_t cn)
{
	uint64_t sector;

	KASSERT(EXFAT_CLUSTER_VALID(pmp, cn),
	    ("exfat_cntodaddr: invalid cluster %u", cn));

	sector = exfat_cluster_to_sector(pmp->pm_cluster_heap_offset,
	    pmp->pm_cluster_shift, cn);

	/* Convert sector to DEV_BSIZE (512-byte) blocks */
	return (sector << (pmp->pm_sector_shift - DEV_BSHIFT));
}

/*
 * Read an entire cluster cn into a buffer cache block.
 *
 * Converts cn to a disk address via exfat_cntodaddr() and issues a
 * synchronous bread() for pm_cluster_size bytes from pm_devvp.
 *
 * Stores the allocated buffer in *bpp on success, or NULL on failure.
 * Returns 0 on success, EINVAL if cn is invalid, or an I/O error from bread().
 */
int
exfat_read_cluster(struct exfat_mount *pmp, uint32_t cn, struct buf **bpp)
{
	daddr_t daddr;
	int error;

	if (!EXFAT_CLUSTER_VALID(pmp, cn)) {
		*bpp = NULL;
		return (EINVAL);
	}

	daddr = exfat_cntodaddr(pmp, cn);
	error = bread(pmp->pm_devvp, daddr, pmp->pm_cluster_size, NOCRED, bpp);
	if (error != 0) {
		if (*bpp != NULL) {
			brelse(*bpp);
			*bpp = NULL;
		}
		return (error);
	}
	return (0);
}

/*
 * Read cluster cn from the device using bread(), with asynchronous read-ahead
 * of next_cn using breadn() if next_cn is valid and read-ahead is enabled.
 *
 * Stores the locked buffer pointer in *bpp.
 * Returns 0 on success, EINVAL if cn is invalid, or an I/O error from bread().
 */
int
exfat_read_cluster_ra(struct exfat_mount *pmp, uint32_t cn, uint32_t next_cn,
    struct buf **bpp)
{
	daddr_t daddr, rablk;
	int rasize;
	int error;

	if (!EXFAT_CLUSTER_VALID(pmp, cn)) {
		*bpp = NULL;
		return (EINVAL);
	}

	daddr = exfat_cntodaddr(pmp, cn);
	if (EXFAT_CLUSTER_VALID(pmp, next_cn) &&
	    (pmp->pm_mountp == NULL ||
	    (pmp->pm_mountp->mnt_flag & MNT_NOCLUSTERR) == 0)) {
		rablk = exfat_cntodaddr(pmp, next_cn);
		rasize = pmp->pm_cluster_size;
		error = breadn(pmp->pm_devvp, daddr, pmp->pm_cluster_size,
		    &rablk, &rasize, 1, NOCRED, bpp);
	} else
		error = bread(pmp->pm_devvp, daddr, pmp->pm_cluster_size,
		    NOCRED, bpp);

	if (error != 0) {
		if (*bpp != NULL) {
			brelse(*bpp);
			*bpp = NULL;
		}
		return (error);
	}
	return (0);
}

/*
 * Initialize a FAT traversal cursor and acquire EXFAT_LOCK.
 *
 * Caches the active FAT sector buffer across consecutive cluster lookups,
 * avoiding repeated buffer cache lookups and lock acquisitions.
 */
void
exfat_fat_cursor_init(struct exfat_mount *pmp, struct exfat_fat_cursor *fc)
{
	fc->fc_pmp = pmp;
	fc->fc_bp = NULL;
	fc->fc_cur_sector = UINT64_MAX;
	fc->fc_fat_offset = pmp->pm_fat_offset;
	if (pmp->pm_vbr.bs_number_of_fats > 1 &&
	    (le16toh(pmp->pm_vbr.bs_volume_flags) & EXFAT_VOL_ACTIVE_FAT))
		fc->fc_fat_offset += pmp->pm_fat_length;
	EXFAT_LOCK(pmp);
}

/*
 * Retrieve the next cluster in a FAT chain using a traversal cursor.
 *
 * If the entry resides in the already-cached FAT sector buffer, returns
 * the value in O(1) time without reading from disk or the buffer cache.
 * When crossing a sector boundary, releases the previous buffer and reads
 * the next FAT sector via bread().
 *
 * Returns 0 on success, EINVAL if cn is invalid, or an I/O error from bread().
 */
int
exfat_fat_cursor_get(struct exfat_fat_cursor *fc, uint32_t cn,
    uint32_t *next_cn)
{
	struct exfat_mount *pmp = fc->fc_pmp;
	uint64_t byte_offset, sector;
	uint32_t bo;
	int error;

	EXFAT_LOCK_ASSERT(pmp);

	if (!EXFAT_CLUSTER_VALID(pmp, cn))
		return (EINVAL);

	byte_offset = (uint64_t)cn * sizeof(uint32_t);
	sector = fc->fc_fat_offset + (byte_offset >> pmp->pm_sector_shift);
	bo = byte_offset & (pmp->pm_sector_size - 1);

	if (fc->fc_bp == NULL || sector != fc->fc_cur_sector) {
		daddr_t daddr;

		if (fc->fc_bp != NULL)
			brelse(fc->fc_bp);
		daddr = sector << (pmp->pm_sector_shift - DEV_BSHIFT);
		error = bread(pmp->pm_devvp, daddr, pmp->pm_sector_size,
		    NOCRED, &fc->fc_bp);
		if (error != 0) {
			if (fc->fc_bp != NULL) {
				brelse(fc->fc_bp);
				fc->fc_bp = NULL;
			}
			fc->fc_cur_sector = UINT64_MAX;
			return (error);
		}
		fc->fc_cur_sector = sector;
	}

	*next_cn = le32dec((const uint8_t *)fc->fc_bp->b_data + bo);
	return (0);
}

/*
 * Release the cached FAT sector buffer and drop EXFAT_LOCK.
 */
void
exfat_fat_cursor_put(struct exfat_fat_cursor *fc)
{
	if (fc->fc_bp != NULL) {
		brelse(fc->fc_bp);
		fc->fc_bp = NULL;
	}
	fc->fc_cur_sector = UINT64_MAX;
	EXFAT_UNLOCK(fc->fc_pmp);
}

/*
 * Look up the next cluster in the FAT chain for cluster cn.
 *
 * Reads the 32-bit FAT entry for cn from the active FAT table (accounting for
 * active FAT selection if multiple FATs exist per VolumeFlags).
 *
 * Stores the 32-bit next cluster value (or EXFAT_FAT_EOF / EXFAT_FAT_FREE) in
 * *next_cn.  Returns 0 on success, EINVAL if cn is invalid, or an I/O error.
 */
int
exfat_fat_get(struct exfat_mount *pmp, uint32_t cn, uint32_t *next_cn)
{
	struct exfat_fat_cursor fc;
	int error;

	exfat_fat_cursor_init(pmp, &fc);
	error = exfat_fat_cursor_get(&fc, cn, next_cn);
	exfat_fat_cursor_put(&fc);
	return (error);
}

/*
 * Set the FAT entry for cluster cn to next_cn.
 *
 * Reads the FAT sector containing cn from the active FAT table, updates the
 * 32-bit entry in little-endian byte order, and writes the buffer back using
 * bdwrite().
 *
 * Returns 0 on success, EINVAL if cn is invalid, or an I/O error from bread().
 */
int
exfat_fat_set(struct exfat_mount *pmp, uint32_t cn, uint32_t next_cn)
{
	struct buf *bp;
	uint64_t fat_offset;
	uint64_t byte_offset;
	uint64_t sector;
	daddr_t daddr;
	uint32_t bo;
	int error;

	if (!EXFAT_CLUSTER_VALID(pmp, cn))
		return (EINVAL);

	fat_offset = pmp->pm_fat_offset;
	if (pmp->pm_vbr.bs_number_of_fats > 1 &&
	    (le16toh(pmp->pm_vbr.bs_volume_flags) & EXFAT_VOL_ACTIVE_FAT))
		fat_offset += pmp->pm_fat_length;

	byte_offset = (uint64_t)cn * sizeof(uint32_t);
	sector = fat_offset + (byte_offset >> pmp->pm_sector_shift);
	bo = byte_offset & (pmp->pm_sector_size - 1);
	daddr = sector << (pmp->pm_sector_shift - DEV_BSHIFT);

	EXFAT_LOCK(pmp);
	error = bread(pmp->pm_devvp, daddr, pmp->pm_sector_size, NOCRED, &bp);
	if (error != 0) {
		if (bp != NULL)
			brelse(bp);
		EXFAT_UNLOCK(pmp);
		return (error);
	}

	le32enc((uint8_t *)bp->b_data + bo, next_cn);
	bdwrite(bp);
	EXFAT_UNLOCK(pmp);
	return (0);
}

/*
 * Clear a range of count consecutive entries in the FAT table to
 * EXFAT_FAT_FREE (0x00000000) starting at start_cn.
 *
 * Iterates through the FAT sectors covering the range, zeroing entries in
 * sector-sized chunks and dirtying each sector with bdwrite().
 *
 * Returns 0 on success, EINVAL if the cluster range is invalid, or an I/O
 * error from reading FAT sectors.
 */
int
exfat_fat_clear_range(struct exfat_mount *pmp, uint32_t start_cn,
    uint32_t count)
{
	uint64_t fat_offset;
	uint32_t cn, end_cn;
	int error;

	if (count == 0)
		return (0);
	if (!EXFAT_CLUSTER_VALID(pmp, start_cn) ||
	    count > pmp->pm_cluster_count - EXFAT_CNTOI(start_cn))
		return (EINVAL);

	fat_offset = pmp->pm_fat_offset;
	if (pmp->pm_vbr.bs_number_of_fats > 1 &&
	    (le16toh(pmp->pm_vbr.bs_volume_flags) & EXFAT_VOL_ACTIVE_FAT))
		fat_offset += pmp->pm_fat_length;

	end_cn = start_cn + count;
	cn = start_cn;

	EXFAT_LOCK(pmp);
	while (cn < end_cn) {
		struct buf *bp;
		uint64_t byte_offset, sector;
		uint32_t bo, entries_in_sec, n;
		daddr_t daddr;

		byte_offset = (uint64_t)cn * sizeof(uint32_t);
		sector = fat_offset + (byte_offset >> pmp->pm_sector_shift);
		bo = byte_offset & (pmp->pm_sector_size - 1);
		daddr = sector << (pmp->pm_sector_shift - DEV_BSHIFT);

		error = bread(pmp->pm_devvp, daddr, pmp->pm_sector_size,
		    NOCRED, &bp);
		if (error != 0) {
			if (bp != NULL)
				brelse(bp);
			EXFAT_UNLOCK(pmp);
			return (error);
		}

		entries_in_sec = (pmp->pm_sector_size - bo) / sizeof(uint32_t);
		n = end_cn - cn;
		if (n > entries_in_sec)
			n = entries_in_sec;

		memset((uint8_t *)bp->b_data + bo, EXFAT_FAT_FREE,
		    n * sizeof(uint32_t));
		bdwrite(bp);
		cn += n;
	}
	EXFAT_UNLOCK(pmp);
	return (0);
}

/*
 * Populate a contiguous range of count entries in the FAT table.
 *
 * Links each entry cn to cn + 1 for start_cn <= cn < start_cn + count - 1,
 * and sets the final entry (start_cn + count - 1) to tail_val (e.g.
 * EXFAT_FAT_EOF or the next cluster in a fragmented chain).
 *
 * Returns 0 on success, EINVAL if the cluster range is invalid, or an I/O
 * error from reading FAT sectors.
 */
int
exfat_fat_link_range(struct exfat_mount *pmp, uint32_t start_cn,
    uint32_t count, uint32_t tail_val)
{
	uint64_t fat_offset;
	uint32_t cn, end_cn;
	int error;

	if (count == 0)
		return (0);
	if (!EXFAT_CLUSTER_VALID(pmp, start_cn) ||
	    count > pmp->pm_cluster_count - EXFAT_CNTOI(start_cn))
		return (EINVAL);

	fat_offset = pmp->pm_fat_offset;
	if (pmp->pm_vbr.bs_number_of_fats > 1 &&
	    (le16toh(pmp->pm_vbr.bs_volume_flags) & EXFAT_VOL_ACTIVE_FAT))
		fat_offset += pmp->pm_fat_length;

	end_cn = start_cn + count;
	cn = start_cn;

	EXFAT_LOCK(pmp);
	while (cn < end_cn) {
		struct buf *bp;
		uint64_t byte_offset, sector;
		uint32_t bo, entries_in_sec, n;
		daddr_t daddr;

		byte_offset = (uint64_t)cn * sizeof(uint32_t);
		sector = fat_offset + (byte_offset >> pmp->pm_sector_shift);
		bo = byte_offset & (pmp->pm_sector_size - 1);
		daddr = sector << (pmp->pm_sector_shift - DEV_BSHIFT);

		error = bread(pmp->pm_devvp, daddr, pmp->pm_sector_size,
		    NOCRED, &bp);
		if (error != 0) {
			if (bp != NULL)
				brelse(bp);
			EXFAT_UNLOCK(pmp);
			return (error);
		}

		entries_in_sec = (pmp->pm_sector_size - bo) / sizeof(uint32_t);
		n = end_cn - cn;
		if (n > entries_in_sec)
			n = entries_in_sec;

		for (uint32_t i = 0; i < n; i++) {
			uint32_t target_cn = (cn + i == end_cn - 1) ?
			    tail_val : (cn + i + 1);

			le32enc((uint8_t *)bp->b_data + bo +
			    i * sizeof(uint32_t), target_cn);
		}

		bdwrite(bp);
		cn += n;
	}
	EXFAT_UNLOCK(pmp);
	return (0);
}

/*
 * Count how many consecutive clusters following start_cn in the FAT chain
 * are physically contiguous (FAT[c] == c + 1), up to maxrun clusters.
 *
 * Used by cluster read/write operations to build multi-cluster contiguous
 * runs for clustering I/O.
 *
 * Stores the contiguous run length in *runp.  Returns 0.
 */
int
exfat_fat_contig_forward(struct exfat_mount *pmp, uint32_t start_cn,
    uint32_t maxrun, int *runp)
{
	struct buf *bp = NULL;
	uint64_t cur_sector = UINT64_MAX, fat_offset;
	uint32_t cn;
	int run = 0;

	*runp = 0;
	if (maxrun == 0 || !EXFAT_CLUSTER_VALID(pmp, start_cn))
		return (0);

	fat_offset = pmp->pm_fat_offset;
	if (pmp->pm_vbr.bs_number_of_fats > 1 &&
	    (le16toh(pmp->pm_vbr.bs_volume_flags) & EXFAT_VOL_ACTIVE_FAT))
		fat_offset += pmp->pm_fat_length;

	cn = start_cn;
	EXFAT_LOCK(pmp);
	while (run < maxrun) {
		uint64_t byte_offset, sector;
		uint32_t bo, next_cn;
		daddr_t daddr;

		if (!EXFAT_CLUSTER_VALID(pmp, cn))
			break;

		byte_offset = (uint64_t)cn * sizeof(uint32_t);
		sector = fat_offset + (byte_offset >> pmp->pm_sector_shift);
		bo = byte_offset & (pmp->pm_sector_size - 1);

		if (bp == NULL || sector != cur_sector) {
			if (bp != NULL)
				brelse(bp);
			daddr = sector << (pmp->pm_sector_shift - DEV_BSHIFT);
			if (bread(pmp->pm_devvp, daddr, pmp->pm_sector_size,
			    NOCRED, &bp) != 0) {
				if (bp != NULL) {
					brelse(bp);
					bp = NULL;
				}
				break;
			}
			cur_sector = sector;
		}

		next_cn = le32dec((uint8_t *)bp->b_data + bo);
		if (next_cn != cn + 1)
			break;

		run++;
		cn++;
	}

	if (bp != NULL)
		brelse(bp);
	EXFAT_UNLOCK(pmp);

	*runp = run;
	return (0);
}

/*
 * Count how many consecutive clusters preceding start_cn in the FAT chain
 * are physically contiguous (FAT[c - 1] == c), up to maxrun clusters.
 *
 * Used by cluster read/write operations to extend contiguous runs backward.
 *
 * Stores the backward contiguous run length in *runb.  Returns 0.
 */
int
exfat_fat_contig_backward(struct exfat_mount *pmp, uint32_t start_cn,
    uint32_t maxrun, int *runb)
{
	struct buf *bp = NULL;
	uint64_t cur_sector = UINT64_MAX, fat_offset;
	uint32_t cn;
	int run = 0;

	*runb = 0;
	if (maxrun == 0 || !EXFAT_CLUSTER_VALID(pmp, start_cn) ||
	    start_cn == EXFAT_FIRST_CLUSTER)
		return (0);

	fat_offset = pmp->pm_fat_offset;
	if (pmp->pm_vbr.bs_number_of_fats > 1 &&
	    (le16toh(pmp->pm_vbr.bs_volume_flags) & EXFAT_VOL_ACTIVE_FAT))
		fat_offset += pmp->pm_fat_length;

	cn = start_cn;
	EXFAT_LOCK(pmp);
	while (run < maxrun) {
		uint64_t byte_offset, sector;
		uint32_t bo, next_cn;
		daddr_t daddr;

		if (cn <= EXFAT_FIRST_CLUSTER)
			break;

		byte_offset = (uint64_t)(cn - 1) * sizeof(uint32_t);
		sector = fat_offset + (byte_offset >> pmp->pm_sector_shift);
		bo = byte_offset & (pmp->pm_sector_size - 1);

		if (bp == NULL || sector != cur_sector) {
			if (bp != NULL)
				brelse(bp);
			daddr = sector << (pmp->pm_sector_shift - DEV_BSHIFT);
			if (bread(pmp->pm_devvp, daddr, pmp->pm_sector_size,
			    NOCRED, &bp) != 0) {
				if (bp != NULL) {
					brelse(bp);
					bp = NULL;
				}
				break;
			}
			cur_sector = sector;
		}

		next_cn = le32dec((uint8_t *)bp->b_data + bo);
		if (next_cn != cn)
			break;

		run++;
		cn--;
	}

	if (bp != NULL)
		brelse(bp);
	EXFAT_UNLOCK(pmp);

	*runb = run;
	return (0);
}

/*
 * Free an entire cluster chain starting at start_cn.
 *
 * If no_fat_chain is true (contiguous stream per Spec §7.6.2), the FAT is
 * unpopulated, so frees all clusters directly from the allocation bitmap.
 *
 * If no_fat_chain is false, traverses the FAT chain up to the number of
 * clusters implied by size (or until EXFAT_FAT_EOF if size == 0), clearing
 * FAT entries to EXFAT_FAT_FREE and clearing corresponding bitmap bits.
 * Consecutive clusters are coalesced into runs to minimize disk I/O.
 *
 * Returns 0 on success, or an I/O error if clearing FAT or bitmap sectors
 * fails.
 */
int
exfat_free_cluster_chain(struct exfat_mount *pmp, uint32_t start_cn,
    bool no_fat_chain, uint64_t size)
{
	uint64_t count64;
	uint32_t cn, count, max_clusters, next_cn, run_start, run_len;
	int error, first_error;

	if (!EXFAT_CLUSTER_VALID(pmp, start_cn))
		return (0);

	if (UINT64_MAX - size < pmp->pm_cluster_mask)
		count64 = pmp->pm_cluster_count;
	else
		count64 = howmany(size, pmp->pm_cluster_size);

	/*
	 * Phase 1: Contiguous stream fast-path.
	 *
	 * When no_fat_chain is true (Spec Section 7.6.2 / 6.4.2), the FAT is
	 * unpopulated. Free the entire contiguous cluster run directly from
	 * the allocation bitmap without reading or modifying FAT sectors.
	 */
	if (no_fat_chain) {
		if (count64 > pmp->pm_cluster_count - EXFAT_CNTOI(start_cn))
			count64 = pmp->pm_cluster_count -
			    EXFAT_CNTOI(start_cn);
		count = (uint32_t)count64;
		if (count == 0)
			count = 1;
		return (exfat_bitmap_free_clusters(pmp, start_cn, count));
	}

	if (count64 == 0 || count64 > pmp->pm_cluster_count)
		max_clusters = pmp->pm_cluster_count;
	else
		max_clusters = (uint32_t)count64;

	first_error = 0;
	EXFAT_LOCK(pmp);
	cn = start_cn;
	count = 0;
	run_start = start_cn;
	run_len = 0;

	/*
	 * Phase 2: Traverse FAT chain and coalesce contiguous runs.
	 *
	 * When size == 0, the loop terminates upon reaching an EOF marker or
	 * invalid cluster (!EXFAT_CLUSTER_VALID), with max_clusters acting as
	 * a cycle guard. When size > 0, count++ < max_clusters terminates the
	 * loop once the expected number of clusters have been freed, protecting
	 * against missing EOF markers or stale unlinked FAT entries.
	 *
	 * Consecutively numbered clusters are batched into runs to minimize
	 * synchronous FAT and bitmap sector writes.
	 */
	while (EXFAT_CLUSTER_VALID(pmp, cn) && count++ < max_clusters) {
		error = exfat_fat_get(pmp, cn, &next_cn);
		if (error != 0) {
			if (first_error == 0)
				first_error = error;
			run_len++;
			break;
		}

		run_len++;
		if (next_cn != cn + 1 || !EXFAT_CLUSTER_VALID(pmp, next_cn)) {
			error = exfat_fat_clear_range(pmp, run_start, run_len);
			if (error != 0 && first_error == 0)
				first_error = error;
			error = exfat_bitmap_free_clusters(pmp, run_start,
			    run_len);
			if (error != 0 && first_error == 0)
				first_error = error;
			run_start = next_cn;
			run_len = 0;
		}

		if (!EXFAT_CLUSTER_VALID(pmp, next_cn))
			break;
		cn = next_cn;
	}

	/*
	 * Phase 3: Flush any remaining coalesced cluster run.
	 */
	if (run_len > 0 && EXFAT_CLUSTER_VALID(pmp, run_start)) {
		error = exfat_fat_clear_range(pmp, run_start, run_len);
		if (error != 0 && first_error == 0)
			first_error = error;
		error = exfat_bitmap_free_clusters(pmp, run_start, run_len);
		if (error != 0 && first_error == 0)
			first_error = error;
	}
	EXFAT_UNLOCK(pmp);
	return (first_error);
}

/*
 * Check whether target_cn is part of the cluster stream starting at start_cn.
 *
 * For contiguous streams (stream_flags has EXFAT_FLAG_NO_FAT_CHAIN), performs
 * an O(1) bounds check against the stream size.  For FAT-chained streams,
 * traverses the chain using exfat_fat_cursor_get() up to the cluster limit
 * implied by size.
 *
 * Returns true if target_cn belongs to the stream, false otherwise.
 */
bool
exfat_cluster_in_chain(struct exfat_mount *pmp, uint32_t start_cn,
    uint8_t stream_flags, uint64_t size, uint32_t target_cn)
{
	struct exfat_fat_cursor fc;
	uint64_t nclusters64;
	uint32_t cn, count, nclusters;

	if (!EXFAT_CLUSTER_VALID(pmp, start_cn) ||
	    !EXFAT_CLUSTER_VALID(pmp, target_cn))
		return (false);

	if (UINT64_MAX - size < pmp->pm_cluster_mask)
		nclusters64 = pmp->pm_cluster_count;
	else
		nclusters64 = howmany(size, pmp->pm_cluster_size);
	if (nclusters64 > pmp->pm_cluster_count)
		nclusters = pmp->pm_cluster_count;
	else
		nclusters = (uint32_t)nclusters64;
	if (nclusters == 0) {
		if ((stream_flags & EXFAT_FLAG_NO_FAT_CHAIN) != 0)
			nclusters = 1;
		else
			nclusters = pmp->pm_cluster_count;
	}

	if ((stream_flags & EXFAT_FLAG_NO_FAT_CHAIN) != 0) {
		if (nclusters > pmp->pm_cluster_count - EXFAT_CNTOI(start_cn))
			nclusters = pmp->pm_cluster_count -
			    EXFAT_CNTOI(start_cn);
		return (target_cn >= start_cn &&
		    target_cn < start_cn + nclusters);
	}

	exfat_fat_cursor_init(pmp, &fc);
	cn = start_cn;
	count = 0;
	while (EXFAT_CLUSTER_VALID(pmp, cn) && count < nclusters) {
		if (cn == target_cn) {
			exfat_fat_cursor_put(&fc);
			return (true);
		}
		count++;
		if (exfat_fat_cursor_get(&fc, cn, &cn) != 0)
			break;
	}
	exfat_fat_cursor_put(&fc);
	return (false);
}

/*
 * Flush a modified range of in-memory allocation bitmap bits to disk.
 *
 * Determines the range of bitmap sectors covering clusters from start_cn to
 * start_cn + count - 1, and for each sector, reads the on-disk sector, copies
 * the updated in-memory bitmap bytes, and issues bdwrite().  Traverses the
 * bitmap's own FAT chain if the bitmap spans multiple clusters.
 *
 * Returns 0 on success, EINVAL if the cluster range is invalid, ELOOP if
 * the cluster index exceeds the cluster count, or an I/O error from bread().
 */
static int
exfat_bitmap_sync_range(struct exfat_mount *pmp, uint32_t start_cn,
    uint32_t count)
{
	uint32_t first_byte, last_byte, first_sec, last_sec;
	uint32_t sec_per_clust, curr_cn, curr_clust_idx;

	EXFAT_LOCK_ASSERT(pmp);

	if (count == 0 || pmp->pm_bitmap == NULL)
		return (0);
	if (!EXFAT_CLUSTER_VALID(pmp, start_cn) ||
	    count > pmp->pm_cluster_count - EXFAT_CNTOI(start_cn))
		return (EINVAL);

	first_byte = EXFAT_CNTOI(start_cn) / 8;
	last_byte = (EXFAT_CNTOI(start_cn) + count - 1) / 8;
	first_sec = first_byte >> pmp->pm_sector_shift;
	last_sec = last_byte >> pmp->pm_sector_shift;
	sec_per_clust = 1U << pmp->pm_cluster_shift;
	curr_cn = pmp->pm_bitmap_cluster;
	curr_clust_idx = 0;

	for (uint32_t sec = first_sec; sec <= last_sec; sec++) {
		uint32_t clust_idx = sec / sec_per_clust;
		uint32_t sec_in_clust = sec % sec_per_clust;
		uint32_t sec_start_byte;
		size_t to_copy;
		struct buf *bp;
		daddr_t daddr;
		int error;

		if (clust_idx >= pmp->pm_cluster_count)
			return (ELOOP);
		while (curr_clust_idx < clust_idx) {
			error = exfat_fat_get(pmp, curr_cn, &curr_cn);
			if (error != 0)
				return (error);
			if (!EXFAT_CLUSTER_VALID(pmp, curr_cn))
				return (EIO);
			curr_clust_idx++;
		}

		daddr = exfat_cntodaddr(pmp, curr_cn) +
		    (sec_in_clust << (pmp->pm_sector_shift - DEV_BSHIFT));

		sec_start_byte = sec << pmp->pm_sector_shift;
		to_copy = pmp->pm_sector_size;
		if (sec_start_byte + to_copy > pmp->pm_bitmap_length)
			to_copy = pmp->pm_bitmap_length - sec_start_byte;

		if (to_copy == pmp->pm_sector_size)
			bp = getblk(pmp->pm_devvp, daddr, pmp->pm_sector_size,
			    0, 0, 0);
		else {
			error = bread(pmp->pm_devvp, daddr,
			    pmp->pm_sector_size, NOCRED, &bp);
			if (error != 0) {
				if (bp != NULL)
					brelse(bp);
				return (error);
			}
		}

		memcpy(bp->b_data, pmp->pm_bitmap + sec_start_byte, to_copy);
		bdwrite(bp);
	}

	return (0);
}

/*
 * Check whether cluster cn is marked as allocated in the in-memory bitmap.
 *
 * Tests the bit corresponding to cn (bit EXFAT_CNTOI(cn)) under EXFAT_LOCK.
 *
 * Returns true if the cluster bit is 1 (allocated), false if 0 (free) or if
 * cn is invalid / bitmap uninitialized.
 */
bool
exfat_bitmap_is_cluster_allocated(struct exfat_mount *pmp, uint32_t cn)
{
	uint32_t idx;
	bool allocated;

	if (pmp == NULL || pmp->pm_bitmap == NULL ||
	    !EXFAT_CLUSTER_VALID(pmp, cn))
		return (false);

	idx = EXFAT_CNTOI(cn);
	EXFAT_LOCK(pmp);
	allocated = (pmp->pm_bitmap[idx / 8] & (1U << (idx % 8))) != 0;
	EXFAT_UNLOCK(pmp);
	return (allocated);
}

/*
 * Set or clear a contiguous range of bits in the allocation bitmap.
 *
 * For partial head and tail bytes, bitwise masks are applied; for fully
 * covered intervening bytes, memset() is used to set or clear bytes in bulk.
 */
static void
exfat_bitmap_set_range(uint8_t *bitmap, uint32_t start_bit, uint32_t count,
    bool val)
{
	uint32_t first_byte, last_byte, mid_start, mid_end;
	uint8_t fill, start_mod, end_mod;

	if (count == 0)
		return;

	first_byte = start_bit / 8;
	last_byte = (start_bit + count - 1) / 8;
	start_mod = start_bit % 8;
	end_mod = (start_bit + count) % 8;

	if (first_byte == last_byte) {
		uint8_t mask;

		/*
		 * Both start and end bits reside in the same byte, so count is
		 * bounded by 1 <= count <= 8 - start_mod <= 8.
		 */
		KASSERT(count <= 8 - start_mod,
		    ("exfat_bitmap_set_range: count %u exceeds byte span",
		    count));
		mask = (uint8_t)(((1U << count) - 1) << start_mod);
		if (val)
			bitmap[first_byte] |= mask;
		else
			bitmap[first_byte] &= ~mask;
		return;
	}

	if (start_mod != 0) {
		uint8_t head_mask = (uint8_t)(0xFFU << start_mod);

		if (val)
			bitmap[first_byte] |= head_mask;
		else
			bitmap[first_byte] &= ~head_mask;
	}

	mid_start = howmany(start_bit, 8);
	mid_end = (start_bit + count) / 8;
	if (mid_end > mid_start) {
		fill = val ? 0xFF : 0x00;
		memset(&bitmap[mid_start], fill, mid_end - mid_start);
	}

	if (end_mod != 0) {
		uint8_t tail_mask = (uint8_t)((1U << end_mod) - 1);

		if (val)
			bitmap[last_byte] |= tail_mask;
		else
			bitmap[last_byte] &= ~tail_mask;
	}
}

/*
 * Allocate a specific contiguous run of count clusters starting at start_cn.
 *
 * Verifies that all bits in the range [start_cn, start_cn + count - 1] are
 * currently free (0).  If so, marks them allocated (1), decrements
 * pm_free_clusters, flushes the bitmap range to disk via
 * exfat_bitmap_sync_range(), and advances pm_last_allocated_cluster.  If
 * syncing fails, rolls back the bitmap bits.
 *
 * Returns 0 on success, ENOSPC if any cluster in the range is already
 * allocated or exceeds volume bounds, EINVAL if bitmap is NULL, or an I/O
 * error.
 */
int
exfat_bitmap_alloc_contiguous_at(struct exfat_mount *pmp, uint32_t start_cn,
    uint32_t count)
{
	uint32_t cn, idx;
	int error;

	if (pmp->pm_bitmap == NULL)
		return (EINVAL);
	if (count == 0)
		return (0);

	if (!EXFAT_CLUSTER_VALID(pmp, start_cn) ||
	    count > pmp->pm_cluster_count - EXFAT_CNTOI(start_cn))
		return (ENOSPC);

	EXFAT_LOCK(pmp);
	/* Check if all bits in the range are free (0) */
	for (cn = start_cn; cn < start_cn + count; cn++) {
		idx = EXFAT_CNTOI(cn);
		if (pmp->pm_bitmap[idx / 8] & (1U << (idx % 8))) {
			EXFAT_UNLOCK(pmp);
			return (ENOSPC);
		}
	}

	/* Mark bits as allocated (1) */
	exfat_bitmap_set_range(pmp->pm_bitmap, EXFAT_CNTOI(start_cn), count,
	    true);
	pmp->pm_free_clusters -= count;

	error = exfat_bitmap_sync_range(pmp, start_cn, count);
	if (error != 0) {
		exfat_bitmap_set_range(pmp->pm_bitmap, EXFAT_CNTOI(start_cn),
		    count, false);
		pmp->pm_free_clusters += count;
		(void)exfat_bitmap_sync_range(pmp, start_cn, count);
		EXFAT_UNLOCK(pmp);
		return (error);
	}

	if (UINT32_MAX - count < start_cn ||
	    !EXFAT_CLUSTER_VALID(pmp, start_cn + count))
		pmp->pm_last_allocated_cluster = EXFAT_FIRST_CLUSTER;
	else if (!EXFAT_CLUSTER_VALID(pmp, pmp->pm_last_allocated_cluster) ||
	    start_cn + count > pmp->pm_last_allocated_cluster)
		pmp->pm_last_allocated_cluster = start_cn + count;

	EXFAT_UNLOCK(pmp);
	return (0);
}

/*
 * Allocate count clusters from the allocation bitmap.
 *
 * Phase 1 searches for a contiguous run of count free clusters starting from
 * the rotor cursor (pm_last_allocated_cluster) and wrapping around.  If found,
 * marks the bits allocated, flushes to disk, and returns with *contigp = true
 * (allowing callers to use EXFAT_FLAG_NO_FAT_CHAIN without writing FAT
 * entries).
 *
 * Phase 2 falls back to allocating fragmented individual free clusters,
 * linking them in the FAT with exfat_fat_set(), terminating with
 * EXFAT_FAT_EOF, and batch-syncing modified bitmap ranges, returning with
 * *contigp = false.
 *
 * Stores the starting cluster number in *start_cnp and contiguity in *contigp.
 * Returns 0 on success, ENOSPC if insufficient free clusters exist, EINVAL if
 * bitmap is NULL, or an I/O error.
 */
int
exfat_bitmap_alloc_clusters(struct exfat_mount *pmp, uint32_t count,
    uint32_t *start_cnp, bool *contigp)
{
	uint32_t total, start_cn, run_start = 0, run_len = 0;
	int error;

	if (pmp->pm_bitmap == NULL)
		return (EINVAL);
	if (count == 0)
		return (0);

	EXFAT_LOCK(pmp);
	/* O(1) early fast-fail if not enough free clusters exist */
	if (pmp->pm_free_clusters < count) {
		EXFAT_UNLOCK(pmp);
		return (ENOSPC);
	}

	start_cn = pmp->pm_last_allocated_cluster;
	if (!EXFAT_CLUSTER_VALID(pmp, start_cn))
		start_cn = EXFAT_FIRST_CLUSTER;

	/*
	 * Phase 1: Search for a contiguous run of 'count' free clusters.
	 *
	 * Contiguous allocation avoids FAT chain traversal and allows setting
	 * the NoFatChain flag in Stream Extension entries (Spec Section
	 * 7.6.2 / 6.4.2), eliminating FAT write overhead.
	 *
	 * The scan starts from the rotor cursor (pm_last_allocated_cluster) to
	 * reduce fragmentation and spread wear, wrapping around to cluster 2
	 * (index 0). The loop condition 'step - run_len < total' ensures we
	 * examine all clusters once without allowing runs to cross the
	 * wraparound boundary.
	 */
	uint32_t curr_idx = EXFAT_CNTOI(start_cn);
	total = pmp->pm_cluster_count;

	for (uint32_t step = 0; step - run_len < total; ) {
		/*
		 * Fast-skip fully allocated clusters when not accumulating a
		 * run. Check aligned 64-bit and 8-bit words; if all bits are
		 * 1 (allocated), skip ahead in large strides instead of
		 * testing bits individually. If a word or byte contains free
		 * clusters, jump directly to the first free cluster bit.
		 */
		if (run_len == 0) {
			if ((curr_idx & 63) == 0 && curr_idx + 64 <= total &&
			    step + 64 <= total) {
				uint64_t val;
				int skip;

				val = le64dec(pmp->pm_bitmap + curr_idx / 8);
				if (val == UINT64_MAX) {
					curr_idx += 64;
					step += 64;
					if (curr_idx == total) {
						curr_idx = 0;
						run_len = 0;
					}
					continue;
				}
				skip = ffsll((long long)~val) - 1;
				if (skip > 0) {
					curr_idx += skip;
					step += skip;
				}
			} else if ((curr_idx & 7) == 0 &&
			    curr_idx + 8 <= total && step + 8 <= total) {
				uint8_t byte;
				int skip;

				byte = pmp->pm_bitmap[curr_idx / 8];
				if (byte == 0xFF) {
					curr_idx += 8;
					step += 8;
					if (curr_idx == total) {
						curr_idx = 0;
						run_len = 0;
					}
					continue;
				}
				skip = ffs((int)(uint8_t)~byte) - 1;
				if (skip > 0) {
					curr_idx += skip;
					step += skip;
				}
			} else if (curr_idx + (8 - (curr_idx & 7)) <= total &&
			    step + (8 - (curr_idx & 7)) <= total) {
				uint8_t b, rem;
				int skip;

				/*
				 * When unaligned (b != 0), test remaining
				 * bits in the current byte (8 - b) if within
				 * cluster heap bounds and search limit. Skip
				 * leading allocated bits in O(1); if the rest
				 * of the byte is fully allocated, advance to
				 * the byte boundary and continue to enter the
				 * aligned 64-bit / 8-bit fast paths.
				 */
				b = curr_idx & 7;
				rem = pmp->pm_bitmap[curr_idx / 8] >> b;
				skip = ffs((int)(uint8_t)~rem) - 1;
				if (skip > 0) {
					curr_idx += skip;
					step += skip;
					if (curr_idx == total) {
						curr_idx = 0;
						run_len = 0;
					}
					if (skip == 8 - b)
						continue;
				}
			}
		}

		uint32_t curr_cn = EXFAT_ITOCN(curr_idx);

		if ((pmp->pm_bitmap[curr_idx / 8] &
		    (1U << (curr_idx % 8))) == 0) {
			if (run_len == 0)
				run_start = curr_cn;
			run_len++;
			if (run_len == count) {
				/*
				 * Contiguous run found: set bits in the
				 * in-memory bitmap, decrement free cluster
				 * count, and synchronously sync the modified
				 * bitmap range to disk.
				 */
				exfat_bitmap_set_range(pmp->pm_bitmap,
				    EXFAT_CNTOI(run_start), count, true);
				pmp->pm_free_clusters -= count;
				error = exfat_bitmap_sync_range(pmp, run_start,
				    count);
				if (error != 0) {
					/* Roll back bitmap on I/O error */
					exfat_bitmap_set_range(pmp->pm_bitmap,
					    EXFAT_CNTOI(run_start), count,
					    false);
					pmp->pm_free_clusters += count;
					(void)exfat_bitmap_sync_range(pmp,
					    run_start, count);
					EXFAT_UNLOCK(pmp);
					return (error);
				}
				/* Advance rotor cursor past the allocation */
				if (UINT32_MAX - count < run_start ||
				    !EXFAT_CLUSTER_VALID(pmp,
				    run_start + count))
					pmp->pm_last_allocated_cluster =
					    EXFAT_FIRST_CLUSTER;
				else
					pmp->pm_last_allocated_cluster =
					    run_start + count;
				*start_cnp = run_start;
				*contigp = true;
				EXFAT_UNLOCK(pmp);
				return (0);
			}
		} else
			run_len = 0;

		curr_idx++;
		step++;
		if (curr_idx == total) {
			curr_idx = 0;
			run_len = 0;
		}
	}

	/*
	 * Phase 2: Fallback to fragmented cluster chain allocation.
	 *
	 * When a contiguous run of count > 1 clusters is unavailable, allocate
	 * individual free clusters wherever they exist and link them together
	 * in the FAT table.
	 *
	 * The scan again starts from the rotor cursor and wraps around. To
	 * minimize disk I/O, bitmap modifications are tracked in at most two
	 * bounding ranges (seg1 for the pre-wrap range, seg2 for the post-wrap
	 * range) and flushed in batch after all clusters are allocated.
	 */
	if (count > 1) {
		uint32_t allocated = 0, first_cn = 0, prev_cn = 0;
		uint32_t seg1_min = 0, seg1_max = 0;
		uint32_t seg2_min = 0, seg2_max = 0;

		curr_idx = EXFAT_CNTOI(start_cn);

		for (uint32_t step = 0;
		    step < total && allocated < count;) {
			/*
			 * Fast-skip fully allocated clusters. Check aligned
			 * 64-bit and 8-bit words; if all bits are 1
			 * (allocated), skip ahead in large strides instead of
			 * testing bits individually. If a word or byte
			 * contains free clusters, jump directly to the first
			 * free cluster bit.
			 */
			if ((curr_idx & 63) == 0 && curr_idx + 64 <= total &&
			    step + 64 <= total) {
				uint64_t val;
				int skip;

				val = le64dec(pmp->pm_bitmap + curr_idx / 8);
				if (val == UINT64_MAX) {
					curr_idx += 64;
					step += 64;
					if (curr_idx == total)
						curr_idx = 0;
					continue;
				}
				skip = ffsll((long long)~val) - 1;
				if (skip > 0) {
					curr_idx += skip;
					step += skip;
				}
			} else if ((curr_idx & 7) == 0 &&
			    curr_idx + 8 <= total && step + 8 <= total) {
				uint8_t byte;
				int skip;

				byte = pmp->pm_bitmap[curr_idx / 8];
				if (byte == 0xFF) {
					curr_idx += 8;
					step += 8;
					if (curr_idx == total)
						curr_idx = 0;
					continue;
				}
				skip = ffs((int)(uint8_t)~byte) - 1;
				if (skip > 0) {
					curr_idx += skip;
					step += skip;
				}
			} else if (curr_idx + (8 - (curr_idx & 7)) <= total &&
			    step + (8 - (curr_idx & 7)) <= total) {
				uint8_t b, rem;
				int skip;

				/*
				 * When unaligned (b != 0), test remaining
				 * bits in the current byte (8 - b) if within
				 * cluster heap bounds and search limit. Skip
				 * leading allocated bits in O(1); if the rest
				 * of the byte is fully allocated, advance to
				 * the byte boundary and continue to enter the
				 * aligned 64-bit / 8-bit fast paths.
				 */
				b = curr_idx & 7;
				rem = pmp->pm_bitmap[curr_idx / 8] >> b;
				skip = ffs((int)(uint8_t)~rem) - 1;
				if (skip > 0) {
					curr_idx += skip;
					step += skip;
					if (curr_idx == total)
						curr_idx = 0;
					if (skip == 8 - b)
						continue;
				}
			}

			uint32_t curr_cn = EXFAT_ITOCN(curr_idx);

			if ((pmp->pm_bitmap[curr_idx / 8] &
			    (1U << (curr_idx % 8))) == 0) {
				/*
				 * Free cluster found: mark allocated in bitmap
				 * and record segment bounds for batched disk
				 * sync.
				 */
				pmp->pm_bitmap[curr_idx / 8] |=
				    (1U << (curr_idx % 8));
				pmp->pm_free_clusters--;

				if (curr_cn >= start_cn) {
					if (seg1_min == 0)
						seg1_min = curr_cn;
					seg1_max = curr_cn;
				} else {
					if (seg2_min == 0)
						seg2_min = curr_cn;
					seg2_max = curr_cn;
				}

				if (allocated == 0)
					first_cn = curr_cn;
				else {
					/*
					 * Link previous cluster to curr_cn in
					 * the FAT.
					 */
					error = exfat_fat_set(pmp, prev_cn,
					    curr_cn);
					if (error != 0) {
						/*
						 * Free curr_cn and roll back
						 * the allocated cluster chain.
						 */
						exfat_bitmap_free_clusters(pmp,
						    curr_cn, 1);
						exfat_free_cluster_chain(pmp,
						    first_cn, false,
						    (uint64_t)allocated *
						    pmp->pm_cluster_size);
						EXFAT_UNLOCK(pmp);
						return (error);
					}
				}
				prev_cn = curr_cn;
				allocated++;
			}

			curr_idx++;
			step++;
			if (curr_idx == total)
				curr_idx = 0;
		}

		if (allocated < count) {
			/* Insufficient clusters found: roll back chain */
			if (first_cn != 0)
				exfat_free_cluster_chain(pmp, first_cn, false,
				    (uint64_t)allocated * pmp->pm_cluster_size);
			EXFAT_UNLOCK(pmp);
			return (ENOSPC);
		}

		/* Terminate the FAT chain with EOF */
		error = exfat_fat_set(pmp, prev_cn, EXFAT_FAT_EOF);
		if (error != 0) {
			exfat_free_cluster_chain(pmp, first_cn, false,
			    (uint64_t)allocated * pmp->pm_cluster_size);
			EXFAT_UNLOCK(pmp);
			return (error);
		}

		/* Batch sync modified bitmap segments to disk */
		if (seg1_min != 0) {
			error = exfat_bitmap_sync_range(pmp, seg1_min,
			    seg1_max - seg1_min + 1);
			if (error != 0) {
				exfat_free_cluster_chain(pmp, first_cn, false,
				    (uint64_t)allocated * pmp->pm_cluster_size);
				EXFAT_UNLOCK(pmp);
				return (error);
			}
		}
		if (seg2_min != 0) {
			error = exfat_bitmap_sync_range(pmp, seg2_min,
			    seg2_max - seg2_min + 1);
			if (error != 0) {
				exfat_free_cluster_chain(pmp, first_cn, false,
				    (uint64_t)allocated * pmp->pm_cluster_size);
				EXFAT_UNLOCK(pmp);
				return (error);
			}
		}

		/* Advance rotor cursor past last allocated cluster */
		if (prev_cn == UINT32_MAX ||
		    !EXFAT_CLUSTER_VALID(pmp, prev_cn + 1))
			pmp->pm_last_allocated_cluster = EXFAT_FIRST_CLUSTER;
		else
			pmp->pm_last_allocated_cluster = prev_cn + 1;
		*start_cnp = first_cn;
		*contigp = false;
		EXFAT_UNLOCK(pmp);
		return (0);
	}

	EXFAT_UNLOCK(pmp);
	return (ENOSPC);
}

/*
 * Free a range of count contiguous clusters in the allocation bitmap starting
 * at start_cn.
 *
 * Clears the corresponding bits in the in-memory bitmap, increments
 * pm_free_clusters, invalidates any buffer cache blocks cached for these
 * clusters on pm_devvp, issues BIO_DELETE (TRIM) via g_delete_data() if TRIM
 * is enabled, updates the allocation rotor cursor, and flushes modified
 * bitmap sectors to disk via exfat_bitmap_sync_range().
 *
 * Returns 0 on success, EINVAL if the cluster range is invalid, or an I/O
 * error from bitmap sync.
 */
int
exfat_bitmap_free_clusters(struct exfat_mount *pmp, uint32_t start_cn,
    uint32_t count)
{
	uint32_t cn, idx;
	int error;

	if (pmp->pm_bitmap == NULL)
		return (0);
	if (count == 0)
		return (0);

	if (!EXFAT_CLUSTER_VALID(pmp, start_cn) ||
	    count > pmp->pm_cluster_count - EXFAT_CNTOI(start_cn))
		return (EINVAL);

	EXFAT_LOCK(pmp);
	for (cn = start_cn; cn < start_cn + count; cn++) {
		struct buf *bp;

		idx = EXFAT_CNTOI(cn);
		if ((pmp->pm_bitmap[idx / 8] & (1U << (idx % 8))) != 0) {
			pmp->pm_bitmap[idx / 8] &= ~(1U << (idx % 8));
			pmp->pm_free_clusters++;
		}
		if (pmp->pm_devvp != NULL) {
			bp = getblk(pmp->pm_devvp, exfat_cntodaddr(pmp, cn),
			    pmp->pm_cluster_size, 0, 0, GB_NOCREAT);
			if (bp != NULL) {
				bp->b_flags |= B_INVAL | B_RELBUF | B_NOCACHE;
				bp->b_flags &= ~(B_ASYNC | B_CACHE);
				brelse(bp);
			}
		}
	}

	/* Rewind rotor cursor to re-use earlier freed clusters */
	if (!EXFAT_CLUSTER_VALID(pmp, pmp->pm_last_allocated_cluster) ||
	    start_cn < pmp->pm_last_allocated_cluster)
		pmp->pm_last_allocated_cluster = start_cn;
	if (!EXFAT_CLUSTER_VALID(pmp, pmp->pm_last_allocated_cluster))
		pmp->pm_last_allocated_cluster = EXFAT_FIRST_CLUSTER;

	if ((pmp->pm_flags & EXFAT_MNT_TRIM) != 0 && pmp->pm_cp != NULL) {
		off_t offset = (off_t)exfat_cntodaddr(pmp, start_cn) *
		    DEV_BSIZE;
		off_t length = (off_t)count * pmp->pm_cluster_size;
		(void)g_delete_data(pmp->pm_cp, offset, length);
	}

	error = exfat_bitmap_sync_range(pmp, start_cn, count);
	EXFAT_UNLOCK(pmp);
	return (error);
}
