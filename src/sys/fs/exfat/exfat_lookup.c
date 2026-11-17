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
#include <sys/buf.h>
#include <sys/clock.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>

#include <fs/exfat/exfat_fat.h>
#include <fs/exfat/exfat_lookup.h>
#include <fs/exfat/exfat_node.h>
#include <fs/exfat/exfat_ondisk.h>
#include <fs/exfat/exfat_unicode.h>
#include <fs/exfat/exfat_vfsops.h>

/*
 * Initialize directory cursor dc to point to the first directory entry
 * of directory dp on mount pmp.
 */
void
exfat_dir_cursor_init(struct exfat_mount *pmp, struct exfat_node *dp,
    struct exfat_dir_cursor *dc)
{
	dc->dc_pmp = pmp;
	dc->dc_dp = dp;
	if (EXFAT_IS_ROOT(dp->node_dirclust, dp->node_diroffset))
		dc->dc_cluster = pmp->pm_rootdir_cluster;
	else
		dc->dc_cluster = dp->node_first_cluster;
	dc->dc_offset = 0;
	dc->dc_bp = NULL;
	dc->dc_clusters_read = 0;
}

/*
 * Retrieve the directory entry at the current position of cursor dc.
 *
 * If the current cluster's buffer is not cached in dc, it is read from disk
 * (with readahead for the next cluster if available).
 *
 * Output arguments:
 *   dentp         - Set to pointer to directory entry in buffer cache.
 *   entry_cluster - If non-NULL, set to the current cluster number.
 *   entry_offset  - If non-NULL, set to byte offset within the current cluster.
 *
 * Returns 0 on success, ENOENT if the cursor cluster is invalid/EOF, or an
 * I/O error from bread/breadn.
 */
int
exfat_dir_cursor_get(struct exfat_dir_cursor *dc,
    const union exfat_dentry **dentp, uint32_t *entry_cluster,
    uint32_t *entry_offset)
{
	struct exfat_mount *pmp = dc->dc_pmp;
	struct exfat_node *dp = dc->dc_dp;
	int error;

	if (!EXFAT_CLUSTER_VALID(pmp, dc->dc_cluster)) {
		*dentp = NULL;
		return (ENOENT);
	}

	if (dc->dc_bp == NULL) {
		uint32_t next_cn = EXFAT_FAT_EOF;

		/* Determine if a valid next cluster exists for read-ahead */
		if (EXFAT_IS_ROOT(dp->node_dirclust, dp->node_diroffset) ||
		    !(dp->node_stream_flags & EXFAT_FLAG_NO_FAT_CHAIN))
			(void)exfat_fat_get(pmp, dc->dc_cluster, &next_cn);
		else if ((uint64_t)(dc->dc_cluster - dp->node_first_cluster +
		    1) * pmp->pm_cluster_size < dp->node_size)
			next_cn = dc->dc_cluster + 1;

		error = exfat_read_cluster_ra(pmp, dc->dc_cluster, next_cn,
		    &dc->dc_bp);
		if (error != 0) {
			exfat_dir_cursor_put(dc);
			*dentp = NULL;
			return (error);
		}
	}

	*dentp = (const union exfat_dentry *)
	    ((const uint8_t *)dc->dc_bp->b_data + dc->dc_offset);
	if (entry_cluster != NULL)
		*entry_cluster = dc->dc_cluster;
	if (entry_offset != NULL)
		*entry_offset = dc->dc_offset;

	return (0);
}

/*
 * Release any cached buffer associated with cursor dc.
 */
void
exfat_dir_cursor_put(struct exfat_dir_cursor *dc)
{
	if (dc->dc_bp != NULL) {
		brelse(dc->dc_bp);
		dc->dc_bp = NULL;
	}
}

/*
 * Advance directory cursor dc to the next directory entry.
 *
 * If crossing a cluster boundary, releases the current buffer and advances
 * along the FAT chain (or contiguous cluster sequence).
 *
 * Returns 0 on success, ELOOP if excessive clusters were traversed, or a
 * FAT access error from exfat_fat_get().
 */
int
exfat_dir_cursor_next(struct exfat_dir_cursor *dc)
{
	struct exfat_mount *pmp = dc->dc_pmp;
	uint32_t next_cn;
	int error;

	dc->dc_offset += sizeof(union exfat_dentry);
	if (dc->dc_offset < pmp->pm_cluster_size)
		return (0);

	/* Cluster boundary reached */
	dc->dc_offset = 0;
	exfat_dir_cursor_put(dc);

	if (++dc->dc_clusters_read > pmp->pm_cluster_count)
		return (ELOOP);

	/* Follow FAT chain or advance contiguous cluster */
	if (EXFAT_IS_ROOT(dc->dc_dp->node_dirclust,
	    dc->dc_dp->node_diroffset) ||
	    !(dc->dc_dp->node_stream_flags & EXFAT_FLAG_NO_FAT_CHAIN)) {
		error = exfat_fat_get(pmp, dc->dc_cluster, &next_cn);
		if (error != 0)
			return (error);
		dc->dc_cluster = next_cn;
	} else if ((uint64_t)dc->dc_clusters_read * pmp->pm_cluster_size >=
	    dc->dc_dp->node_size)
		dc->dc_cluster = EXFAT_FAT_EOF;
	else
		dc->dc_cluster++;

	return (0);
}

/*
 * Skip count directory entries from the current cursor position.
 *
 * If the skipped entries remain within the current cluster, dc_offset is
 * advanced directly in O(1) time without reading or releasing buffers. If
 * crossing a cluster boundary, releases the current buffer and advances along
 * the FAT chain (or contiguous cluster sequence) via exfat_dir_cursor_next().
 *
 * Returns 0 on success, or an error from exfat_dir_cursor_next().
 */
int
exfat_dir_cursor_skip(struct exfat_dir_cursor *dc, uint32_t count)
{
	struct exfat_mount *pmp = dc->dc_pmp;
	int error;

	while (count > 0) {
		uint32_t entries_rem;

		entries_rem = (pmp->pm_cluster_size - dc->dc_offset) /
		    sizeof(union exfat_dentry);
		if (count < entries_rem) {
			dc->dc_offset += count * sizeof(union exfat_dentry);
			return (0);
		}
		count -= entries_rem;
		dc->dc_offset = pmp->pm_cluster_size -
		    sizeof(union exfat_dentry);
		error = exfat_dir_cursor_next(dc);
		if (error != 0)
			return (error);
	}
	return (0);
}

/*
 * Position directory cursor dc at logical byte offset target_disk_offset
 * from the start of directory dp on mount pmp.
 *
 * Traverses clusters up to target_disk_offset / cluster_size.
 *
 * Returns 0 on success, ENOENT if offset exceeds directory stream length or
 * hits EOF, ELOOP if traversing more clusters than the filesystem cluster
 * count, or a FAT access error.
 */
int
exfat_dir_cursor_seek(struct exfat_mount *pmp, struct exfat_node *dp,
    struct exfat_dir_cursor *dc, uint32_t target_disk_offset)
{
	uint32_t cluster_idx = target_disk_offset / pmp->pm_cluster_size;
	uint32_t offset = target_disk_offset & pmp->pm_cluster_mask;
	uint32_t cn;
	bool is_root;
	int error;

	dc->dc_pmp = pmp;
	dc->dc_dp = dp;
	dc->dc_bp = NULL;

	is_root = EXFAT_IS_ROOT(dp->node_dirclust, dp->node_diroffset);
	if (is_root)
		cn = pmp->pm_rootdir_cluster;
	else
		cn = dp->node_first_cluster;

	if (!is_root && (dp->node_stream_flags & EXFAT_FLAG_NO_FAT_CHAIN)) {
		if ((uint64_t)target_disk_offset >= dp->node_size ||
		    !EXFAT_CLUSTER_VALID(pmp, cn) ||
		    cluster_idx >= pmp->pm_cluster_count ||
		    UINT32_MAX - cn < cluster_idx ||
		    !EXFAT_CLUSTER_VALID(pmp, cn + cluster_idx)) {
			dc->dc_cluster = EXFAT_FAT_EOF;
			dc->dc_offset = 0;
			dc->dc_clusters_read = cluster_idx;
			return (ENOENT);
		}
		cn += cluster_idx;
	} else {
		struct exfat_fat_cursor fc;
		uint32_t start_idx = 0;

		/*
		 * Check directory cluster cache.
		 *
		 * Both cache lookups require fc_frcn <= cluster_idx, so
		 * start_idx is only advanced when a cached cluster precedes
		 * or matches the seek target. If seeking backward (e.g.
		 * rewinddir), both conditions evaluate to false, leaving
		 * start_idx at 0 and cn at the directory's first cluster to
		 * safely restart traversal from the beginning.
		 *
		 * This guarantees the invariant: 0 <= start_idx <= cluster_idx.
		 */
		if (dp->node_fc[EXFAT_FC_LASTMAP].fc_frcn != EXFAT_FCE_EMPTY &&
		    dp->node_fc[EXFAT_FC_LASTMAP].fc_frcn <= cluster_idx) {
			if (EXFAT_CLUSTER_VALID(pmp,
			    dp->node_fc[EXFAT_FC_LASTMAP].fc_fsrcn)) {
				start_idx =
				    dp->node_fc[EXFAT_FC_LASTMAP].fc_frcn;
				cn = dp->node_fc[EXFAT_FC_LASTMAP].fc_fsrcn;
			} else {
				dp->node_fc[EXFAT_FC_LASTMAP].fc_frcn =
				    EXFAT_FCE_EMPTY;
				dp->node_fc[EXFAT_FC_LASTMAP].fc_fsrcn =
				    EXFAT_FCE_EMPTY;
			}
		}
		if (dp->node_fc[EXFAT_FC_LASTFC].fc_frcn != EXFAT_FCE_EMPTY &&
		    dp->node_fc[EXFAT_FC_LASTFC].fc_frcn <= cluster_idx &&
		    dp->node_fc[EXFAT_FC_LASTFC].fc_frcn > start_idx) {
			if (EXFAT_CLUSTER_VALID(pmp,
			    dp->node_fc[EXFAT_FC_LASTFC].fc_fsrcn)) {
				start_idx =
				    dp->node_fc[EXFAT_FC_LASTFC].fc_frcn;
				cn = dp->node_fc[EXFAT_FC_LASTFC].fc_fsrcn;
			} else {
				dp->node_fc[EXFAT_FC_LASTFC].fc_frcn =
				    EXFAT_FCE_EMPTY;
				dp->node_fc[EXFAT_FC_LASTFC].fc_fsrcn =
				    EXFAT_FCE_EMPTY;
			}
		}

		KASSERT(start_idx <= cluster_idx,
		    ("exfat_dir_cursor_seek: start_idx %u > cluster_idx %u",
		    start_idx, cluster_idx));

		if (cluster_idx > pmp->pm_cluster_count)
			return (ELOOP);
		exfat_fat_cursor_init(pmp, &fc);
		for (uint32_t i = start_idx; i < cluster_idx; i++) {
			if (!EXFAT_CLUSTER_VALID(pmp, cn)) {
				exfat_fat_cursor_put(&fc);
				dc->dc_cluster = EXFAT_FAT_EOF;
				dc->dc_offset = 0;
				dc->dc_clusters_read = i;
				return (ENOENT);
			}
			error = exfat_fat_cursor_get(&fc, cn, &cn);
			if (error != 0) {
				exfat_fat_cursor_put(&fc);
				return (error);
			}
		}
		exfat_fat_cursor_put(&fc);
		if (!EXFAT_CLUSTER_VALID(pmp, cn)) {
			dc->dc_cluster = EXFAT_FAT_EOF;
			dc->dc_offset = 0;
			dc->dc_clusters_read = cluster_idx;
			return (ENOENT);
		}

		/* Update directory cluster cache */
		dp->node_fc[EXFAT_FC_LASTMAP].fc_frcn = cluster_idx;
		dp->node_fc[EXFAT_FC_LASTMAP].fc_fsrcn = cn;
	}

	dc->dc_cluster = cn;
	dc->dc_offset = offset;
	dc->dc_clusters_read = cluster_idx;
	return (0);
}

/*
 * Advance to the next cluster in a directory's cluster stream.
 *
 * For directories with a FAT chain (including the root directory), queries
 * the FAT for cluster cn.  For contiguous streams (EXFAT_FLAG_NO_FAT_CHAIN),
 * advances to cn + 1 until the directory's size is reached.
 *
 * Returns 0 on success with the next cluster (or EXFAT_FAT_EOF) stored in
 * *next_cnp, or an I/O error from FAT access.
 */
static int
exfat_dir_next_cluster(struct exfat_mount *pmp, struct exfat_node *dp,
    uint32_t cn, uint32_t *next_cnp)
{
	KASSERT(dp != NULL, ("exfat_dir_next_cluster: NULL dp"));

	if (EXFAT_IS_ROOT(dp->node_dirclust, dp->node_diroffset) ||
	    (dp->node_stream_flags & EXFAT_FLAG_NO_FAT_CHAIN) == 0)
		return (exfat_fat_get(pmp, cn, next_cnp));
	if (cn >= dp->node_first_cluster &&
	    (uint64_t)(cn - dp->node_first_cluster + 1) *
	    pmp->pm_cluster_size < dp->node_size &&
	    EXFAT_CLUSTER_VALID(pmp, cn + 1))
		*next_cnp = cn + 1;
	else
		*next_cnp = EXFAT_FAT_EOF;
	return (0);
}

/*
 * XXX Advance to the next cluster when reading, writing, or deleting a
 * directory entry set across a cluster boundary.  This is a variant of
 * exfat_dir_next_cluster() with a fallback compromise for callers that cannot
 * provide a parent directory node (dp == NULL).
 *
 * When the parent directory node is known (dp != NULL), it delegates to
 * exfat_dir_next_cluster() which resolves the next cluster using dp's
 * verified stream flags and size.
 *
 * Problem / limitation:
 * When dp is NULL, this function queries the FAT.  If FAT[cn] is
 * EXFAT_FAT_FREE, it assumes the directory stream is contiguous and
 * advances to cn + 1.  dp is NULL in three cases:
 * 1. exfat_node_load(): Loading an un-cached inode into memory when only
 *    its locator (dirclust, diroffset) is known.
 * 2. exfat_node_sync(): Syncing inode metadata back to disk without holding
 *    a reference to its parent directory node.
 * 3. exfat_checkpath(): Walking ancestor directories during rename when an
 *    ancestor vnode is not in the active cache.
 *
 * The problems with assuming cn + 1 when dp is NULL are:
 * 1. EXFAT_FLAG_NO_FAT_CHAIN is never verified because the directory's
 *    stream flags are unknown when dp == NULL, and DataLength bounds are
 *    not enforced.
 * 2. Per exFAT Spec §7.6.2 / §6.4.2, FAT entries for NoFatChain
 *    streams are invalid / undefined, not guaranteed to be EXFAT_FAT_FREE (0).
 *    Implementations do not update or zero the FAT for contiguous streams,
 *    so stale cluster indices may remain in the FAT, causing false negatives.
 * 3. Conversely, if a FAT-chained directory has an unallocated or corrupt
 *    FAT entry of 0, this assumption falsely treats it as contiguous (false
 *    positive) and advances into cn + 1 rather than detecting corruption.
 *    Checking that cn is not the root directory cluster (which must always
 *    use a FAT chain per Spec §3.1.10) and that cn + 1 is allocated in the
 *    bitmap helps improve accuracy, but does not eliminate the fundamental
 *    limitation: cn + 1 could belong to an entirely different file.
 */
static int
exfat_dir_next_cluster_fallback(struct exfat_mount *pmp,
    struct exfat_node *dp, uint32_t cn, uint32_t *next_cnp)
{
	uint32_t next_cn;
	int error;

	if (dp != NULL) {
		error = exfat_dir_next_cluster(pmp, dp, cn, &next_cn);
		if (error != 0)
			return (error);
		/*
		 * exfat_dir_next_cluster() returns 0 with next_cn = EOF when
		 * reaching the end of a directory chain (which normal directory
		 * scanners like exfat_dentry_find_free_slot use to terminate
		 * scanning or allocate new clusters).  However, because
		 * fallback callers are in the middle of processing an entry set
		 * across a cluster boundary, hitting EOF or an invalid cluster
		 * here is an error (truncated on-disk entry set).
		 */
		if (!EXFAT_CLUSTER_VALID(pmp, next_cn))
			return (EIO);
		*next_cnp = next_cn;
		return (0);
	}

	error = exfat_fat_get(pmp, cn, &next_cn);
	if (error != 0)
		return (error);

	/*
	 * When dp == NULL (exfat_node_load, exfat_node_sync, or
	 * exfat_checkpath), directory stream flags and size are unknown.
	 *
	 * 1. Root directory: Per Microsoft exFAT Spec §3.1.10
	 *    (FirstClusterOfRootDirectory Field), the root directory always
	 *    uses a FAT chain; an entry of 0 is unallocated and corrupt (EIO).
	 * 2. Subdirectories: Per Spec §7.6.2 / §6.4.2, FAT entries for
	 *    NoFatChain streams are undefined (and often left unpopulated as
	 *    0). If FAT[cn] == 0, only advance to cn + 1 if cn is not the
	 *    root directory cluster, cn + 1 is valid, and cn + 1 is confirmed
	 *    allocated in the cluster allocation bitmap (Spec §7.1). Even so,
	 *    cn + 1 may not actually belong to this directory.
	 */
	if (next_cn == EXFAT_FAT_FREE) {
		if (cn == pmp->pm_rootdir_cluster)
			return (EIO);
		if (EXFAT_CLUSTER_VALID(pmp, cn + 1) &&
		    exfat_bitmap_is_cluster_allocated(pmp, cn + 1))
			next_cn = cn + 1;
		else
			return (EIO);
	} else if (!EXFAT_CLUSTER_VALID(pmp, next_cn))
		return (EIO);

	KASSERT(EXFAT_CLUSTER_VALID(pmp, next_cn),
	    ("exfat_dir_next_cluster_fallback: invalid next_cn %u", next_cn));
	*next_cnp = next_cn;
	return (0);
}

/*
 * Read a complete directory entry set (primary 0x85 entry plus all secondary
 * entries) starting at (dirclust, diroffset), crossing cluster boundaries
 * if the entry set straddles two clusters.
 */
int
exfat_dentry_read_set(struct exfat_mount *pmp, struct exfat_node *dp,
    uint32_t dirclust, uint32_t diroffset, union exfat_dentry *dentries,
    uint8_t *countp)
{
	struct buf *bp;
	const union exfat_dentry *dent;
	uint32_t cn, offset;
	uint8_t num_name_entries, secondary_count, total, i;
	int error;

	if (pmp == NULL || !EXFAT_CLUSTER_VALID(pmp, dirclust))
		return (ESTALE);

	if ((diroffset % sizeof(union exfat_dentry)) != 0 ||
	    diroffset >= pmp->pm_cluster_size)
		return (ESTALE);

	cn = dirclust;
	offset = diroffset;
	error = exfat_read_cluster(pmp, cn, &bp);
	if (error != 0)
		return (error);

	dent = (const union exfat_dentry *)((const uint8_t *)bp->b_data +
	    offset);
	if (dent->type != EXFAT_ENTRY_FILE) {
		brelse(bp);
		return (ESTALE);
	}

	secondary_count = dent->file.fe_secondary_count;
	if (secondary_count < EXFAT_MIN_SECONDARY_COUNT ||
	    secondary_count > EXFAT_MAX_SECONDARY_COUNT) {
		brelse(bp);
		return (ESTALE);
	}

	total = 1 + secondary_count;

	/*
	 * Fast path: if the entire directory entry set resides contiguously
	 * within the current cluster buffer, copy it in a single block rather
	 * than iterating entry-by-entry.
	 */
	if (offset + (uint32_t)total * sizeof(union exfat_dentry) <=
	    pmp->pm_cluster_size) {
		memcpy(dentries, (const uint8_t *)bp->b_data + offset,
		    total * sizeof(union exfat_dentry));
	} else {
		dentries[0] = *dent;
		for (i = 1; i < total; i++) {
			offset += sizeof(union exfat_dentry);
			if (offset >= pmp->pm_cluster_size) {
				brelse(bp);
				bp = NULL;
				offset = 0;

				error = exfat_dir_next_cluster_fallback(pmp, dp,
				    cn, &cn);
				if (error != 0)
					return (ESTALE);

				error = exfat_read_cluster(pmp, cn, &bp);
				if (error != 0)
					return (error);
			}
			dent = (const union exfat_dentry *)
			    ((const uint8_t *)bp->b_data + offset);
			dentries[i] = *dent;
		}
	}

	brelse(bp);

	if (dentries[1].type != EXFAT_ENTRY_STREAM)
		return (ESTALE);
	num_name_entries = howmany(dentries[1].stream.se_name_length,
	    EXFAT_CHARS_PER_NAME_ENTRY);
	if (dentries[1].stream.se_name_length == 0 ||
	    secondary_count < 1 + num_name_entries)
		return (ESTALE);
	for (i = 2; i < total; i++) {
		if (i <= 1 + num_name_entries) {
			if (dentries[i].type != EXFAT_ENTRY_NAME)
				return (ESTALE);
		} else if ((dentries[i].type & (EXFAT_ENTRY_TYPE_IN_USE |
		    EXFAT_ENTRY_TYPE_SECONDARY | EXFAT_ENTRY_TYPE_BENIGN)) !=
		    (EXFAT_ENTRY_TYPE_IN_USE | EXFAT_ENTRY_TYPE_SECONDARY |
		    EXFAT_ENTRY_TYPE_BENIGN)) {
			/*
			 * Trailing secondary entries (e.g. Vendor Extension
			 * 0xE0 or Vendor Allocation 0xE1 per Spec §7.8/§7.9)
			 * must be in-use benign secondary entries per
			 * Spec §6.2.1 and §6.4.1.2.2.
			 */
			return (ESTALE);
		}
	}

	/*
	 * Verify SetChecksum (Spec §6.3.3 / §7.4.3). Implementations
	 * shall verify the checksum is valid before trusting or using
	 * any other directory entry in the set; omitting this check is
	 * a specification compliance defect.
	 */
	if (le16toh(dentries[0].file.fe_set_checksum) !=
	    exfat_dentry_calc_checksum(dentries, total))
		return (ESTALE);

	if (countp != NULL)
		*countp = total;
	return (0);
}

/*
 * Write a directory entry set of count entries starting at
 * (dirclust, diroffset), crossing cluster boundaries if necessary.
 */
int
exfat_dentry_write_set(struct exfat_mount *pmp, struct exfat_node *dp,
    uint32_t dirclust, uint32_t diroffset, const union exfat_dentry *dentries,
    uint8_t count)
{
	struct buf *bp;
	uint32_t cn, offset, avail, chunk;
	uint8_t written;
	int error;

	if (pmp == NULL || !EXFAT_CLUSTER_VALID(pmp, dirclust) ||
	    (diroffset % sizeof(union exfat_dentry)) != 0 ||
	    diroffset >= pmp->pm_cluster_size || count == 0)
		return (EINVAL);

	cn = dirclust;
	offset = diroffset;
	written = 0;

	while (written < count) {
		error = exfat_read_cluster(pmp, cn, &bp);
		if (error != 0) {
			if (written > 0)
				(void)exfat_dentry_delete_set(pmp, dp,
				    dirclust, diroffset, written);
			return (error);
		}

		avail = (pmp->pm_cluster_size - offset) /
		    sizeof(union exfat_dentry);
		chunk = count - written;
		if (chunk > avail)
			chunk = avail;

		memcpy((uint8_t *)bp->b_data + offset, &dentries[written],
		    chunk * sizeof(union exfat_dentry));
		bdwrite(bp);

		written += chunk;
		offset = 0;

		if (written < count) {
			error = exfat_dir_next_cluster_fallback(pmp, dp, cn,
			    &cn);
			if (error != 0) {
				(void)exfat_dentry_delete_set(pmp, dp,
				    dirclust, diroffset, written);
				return (error);
			}
		}
	}

	return (0);
}

/*
 * Delete a directory entry set of count entries starting at
 * (dirclust, diroffset) by clearing EXFAT_ENTRY_TYPE_IN_USE on each entry,
 * crossing cluster boundaries if necessary.
 */
int
exfat_dentry_delete_set(struct exfat_mount *pmp, struct exfat_node *dp,
    uint32_t dirclust, uint32_t diroffset, uint8_t count)
{
	struct buf *bp;
	union exfat_dentry *dent;
	uint32_t cn, offset, avail, chunk, i;
	uint8_t deleted;
	int error;

	if (pmp == NULL || !EXFAT_CLUSTER_VALID(pmp, dirclust) ||
	    (diroffset % sizeof(union exfat_dentry)) != 0 ||
	    diroffset >= pmp->pm_cluster_size || count == 0)
		return (EINVAL);

	cn = dirclust;
	offset = diroffset;
	deleted = 0;

	while (deleted < count) {
		error = exfat_read_cluster(pmp, cn, &bp);
		if (error != 0)
			return (error);

		avail = (pmp->pm_cluster_size - offset) /
		    sizeof(union exfat_dentry);
		chunk = count - deleted;
		if (chunk > avail)
			chunk = avail;

		dent = (union exfat_dentry *)((uint8_t *)bp->b_data + offset);
		for (i = 0; i < chunk; i++)
			dent[i].type &= ~EXFAT_ENTRY_TYPE_IN_USE;

		bdwrite(bp);
		deleted += chunk;
		offset = 0;

		if (deleted < count) {
			error = exfat_dir_next_cluster_fallback(pmp, dp, cn,
			    &cn);
			if (error != 0)
				return (error);
		}
	}

	return (0);
}

/*
 * Find a contiguous slot of count free or deleted directory entries in
 * directory dp.
 *
 * Scans existing directory clusters for a contiguous run of count slots
 * starting from the directory's hint cursor (wrapping around to the first
 * cluster if needed).  If no existing slot is large enough, allocates and
 * initializes new clusters to extend the directory.
 *
 * Output arguments:
 *   slot_clusterp - Set to cluster containing the first entry of the slot.
 *   slot_offsetp  - Set to byte offset within slot_clusterp of the first entry.
 *
 * Returns 0 on success, ENOSPC if disk space is exhausted, EFBIG if extending
 * exceeds max directory size, or an I/O error.
 */
int
exfat_dentry_find_free_slot(struct exfat_node *dp, uint8_t count,
    uint32_t *slot_clusterp, uint32_t *slot_offsetp)
{
	struct exfat_mount *pmp = dp->node_pmp;
	uint32_t first_cn, cn, next_cn, last_cn;
	uint32_t entries_per_clust, needed_clusters;
	uint32_t first_new_cn = 0, last_new_cn = 0;
	uint32_t start_clust, start_offset;
	uint32_t run_len = 0, run_start_clust = 0, run_start_offset = 0;
	bool contig, had_no_fat_chain, wrapped = false;
	struct buf *bp;
	int error;

	entries_per_clust = pmp->pm_cluster_size / sizeof(union exfat_dentry);
	if (entries_per_clust == 0)
		return (EINVAL);

	if (EXFAT_IS_ROOT(dp->node_dirclust, dp->node_diroffset))
		first_cn = pmp->pm_rootdir_cluster;
	else
		first_cn = dp->node_first_cluster;

	/* Determine search start point from hint cursor if valid */
	if (EXFAT_CLUSTER_VALID(pmp, dp->node_dir_hint_clust)) {
		start_clust = dp->node_dir_hint_clust;
		start_offset = dp->node_dir_hint_offset;
	} else {
		start_clust = first_cn;
		start_offset = 0;
	}

	if (start_offset >= pmp->pm_cluster_size) {
		error = exfat_dir_next_cluster(pmp, dp, start_clust, &next_cn);
		if (error == 0 && EXFAT_CLUSTER_VALID(pmp, next_cn)) {
			start_clust = next_cn;
			start_offset = 0;
		} else {
			start_clust = first_cn;
			start_offset = 0;
		}
	}

	cn = start_clust;
	last_cn = first_cn;

	/*
	 * Phase 1: Search existing directory clusters for a contiguous run of
	 * 'count' free or unallocated directory entries.
	 *
	 * To optimize sequential file creations, the search starts from the
	 * cached hint cursor (start_clust, start_offset). If reaching EOF
	 * without finding a sufficient run, wrap around to first_cn to inspect
	 * any earlier slots freed by file deletions. If trailing free entries
	 * exist at the very end of the directory, their count is preserved in
	 * run_len so new clusters only need to accommodate the remaining
	 * entries.
	 */
	while (1) {
		uint32_t walked = 0;

		run_len = 0;
		while (EXFAT_CLUSTER_VALID(pmp, cn)) {
			const union exfat_dentry *dent;
			uint32_t start_idx = 0;

			if (++walked > pmp->pm_cluster_count)
				return (ELOOP);

			last_cn = cn;
			error = exfat_dir_next_cluster(pmp, dp, cn, &next_cn);
			if (error != 0)
				return (error);

			error = exfat_read_cluster_ra(pmp, cn, next_cn, &bp);
			if (error != 0)
				return (error);

			dent = (const union exfat_dentry *)bp->b_data;
			/*
			 * Apply start_offset only on the very first cluster of
			 * the initial pre-wrap pass. Subsequent clusters, as
			 * well as any full wraparound pass from first_cn, scan
			 * every entry starting from index 0.
			 */
			if (cn == start_clust && !wrapped) {
				start_idx = start_offset /
				    sizeof(union exfat_dentry);
				if (start_idx >= entries_per_clust)
					start_idx = 0;

				/*
				 * If the hint offset lands past an earlier
				 * EXFAT_ENTRY_EOD (0x00) marker within the
				 * cluster (e.g. after an error rollback),
				 * restart from offset 0 so we do not allocate
				 * entries after an earlier 0x00, which would
				 * make them invisible to spec-compliant
				 * directory traversals (Spec §6.2.1).
				 */
				if (start_idx > 0 &&
				    dent[start_idx].type == EXFAT_ENTRY_EOD &&
				    dent[start_idx - 1].type ==
				    EXFAT_ENTRY_EOD)
					start_idx = 0;

				/*
				 * If the hint cluster itself begins with an
				 * EOD entry and is not the first cluster, an
				 * earlier cluster may contain the first EOD
				 * entry. Wrap around to scan from first_cn.
				 */
				if (start_idx == 0 &&
				    start_clust != first_cn &&
				    dent[0].type == EXFAT_ENTRY_EOD) {
					brelse(bp);
					wrapped = true;
					cn = first_cn;
					break;
				}
				run_len = 0;
			}
			for (uint32_t i = start_idx;
			    i < entries_per_clust; i++) {
				uint8_t type = dent[i].type;

				/*
				 * Per exFAT Spec §6.2.1, 00h is an end-of-
				 * directory (EOD) marker and all subsequent
				 * directory entries in the directory are also
				 * EOD markers, which implementations may
				 * overwrite as necessary.
				 *
				 * Clusters in exFAT are never shared between
				 * files or directories. Because a directory's
				 * size is always an exact multiple of the
				 * cluster size (Spec §7.6.7), every 32-byte
				 * slot in every cluster allocated to that
				 * directory belongs to that directory. Thus,
				 * all remaining entries in this cluster are
				 * available free slots; absorb them in O(1)
				 * instead of inspecting each slot individually.
				 */
				if (type == EXFAT_ENTRY_EOD) {
					uint32_t entries_rem =
					    entries_per_clust - i;

					if (run_len == 0) {
						run_start_clust = cn;
						run_start_offset = i *
						    sizeof(union exfat_dentry);
					}
					if (run_len + entries_rem >= count) {
						uint32_t needed =
						    count - run_len;

						brelse(bp);
						*slot_clusterp =
						    run_start_clust;
						*slot_offsetp =
						    run_start_offset;
						dp->node_dir_hint_clust = cn;
						dp->node_dir_hint_offset =
						    (i + needed) *
						    sizeof(union exfat_dentry);
						return (0);
					}
					run_len += entries_rem;
					break;
				}
				if ((type & EXFAT_ENTRY_TYPE_IN_USE) == 0) {
					if (run_len == 0) {
						run_start_clust = cn;
						run_start_offset = i *
						    sizeof(union exfat_dentry);
					}
					run_len++;
					if (run_len == count) {
						brelse(bp);
						*slot_clusterp =
						    run_start_clust;
						*slot_offsetp =
						    run_start_offset;
						dp->node_dir_hint_clust = cn;
						dp->node_dir_hint_offset =
						    (i + 1) *
						    sizeof(union exfat_dentry);
						return (0);
					}
				} else
					run_len = 0;
			}

			brelse(bp);
			cn = next_cn;
		}

		/*
		 * If we broke out early to wrap around to first_cn (or
		 * reached EOF after starting at a hint), restart from the
		 * beginning of the directory.
		 */
		if (wrapped && cn == first_cn)
			continue;
		if (!wrapped &&
		    (start_clust != first_cn || start_offset != 0)) {
			wrapped = true;
			cn = first_cn;
			continue;
		}

		break;
	}

	/*
	 * Phase 2: Directory expansion.
	 *
	 * Existing clusters do not have 'count' contiguous free slots. If
	 * run_len > 0, the trailing free slots at the end of the last cluster
	 * form the start of the entry set, and the set will straddle into the
	 * newly allocated cluster(s). Only the remaining (count - run_len)
	 * entries need to be allocated in new clusters.
	 *
	 * Allocate needed_clusters in bulk from the bitmap, zero each
	 * cluster's contents in core so all entries default to unallocated
	 * (EXFAT_ENTRY_EOD), and link them together in the FAT.
	 */
	needed_clusters = howmany(count - run_len, entries_per_clust);
	if (dp->node_size > EXFAT_MAX_DIR_SIZE -
	    (uint64_t)needed_clusters * pmp->pm_cluster_size)
		return (EFBIG);

	error = exfat_bitmap_alloc_clusters(pmp, needed_clusters,
	    &first_new_cn, &contig);
	if (error != 0)
		return (error);

	if (contig) {
		for (uint32_t c = 0; c < needed_clusters; c++) {
			bp = getblk(pmp->pm_devvp,
			    exfat_cntodaddr(pmp, first_new_cn + c),
			    pmp->pm_cluster_size, 0, 0, 0);
			vfs_bio_clrbuf(bp);
			bdwrite(bp);
		}

		error = exfat_fat_link_range(pmp, first_new_cn,
		    needed_clusters, EXFAT_FAT_EOF);
		if (error != 0) {
			(void)exfat_fat_clear_range(pmp, first_new_cn,
			    needed_clusters);
			exfat_bitmap_free_clusters(pmp, first_new_cn,
			    needed_clusters);
			return (error);
		}
		last_new_cn = first_new_cn + needed_clusters - 1;
	} else {
		uint32_t curr_cn = first_new_cn;

		for (uint32_t c = 0; c < needed_clusters; c++) {
			bp = getblk(pmp->pm_devvp,
			    exfat_cntodaddr(pmp, curr_cn),
			    pmp->pm_cluster_size, 0, 0, 0);
			vfs_bio_clrbuf(bp);
			bdwrite(bp);

			last_new_cn = curr_cn;
			if (c + 1 < needed_clusters) {
				error = exfat_fat_get(pmp, curr_cn, &curr_cn);
				if (error != 0) {
					exfat_free_cluster_chain(pmp,
					    first_new_cn, false, 0);
					return (error);
				}
			}
		}
	}

	/*
	 * Phase 3: Connect existing directory cluster chain to the new
	 * clusters.
	 *
	 * exFAT Spec Section 7.6.2 / 6.4.2 (NoFatChain field): When a
	 * contiguous directory (NoFatChain=1) is extended with additional
	 * clusters, the chain may no longer be physically contiguous. We
	 * convert it to a FAT chain by populating intermediate FAT entries for
	 * the existing clusters before appending first_new_cn and clearing
	 * NoFatChain.
	 */
	had_no_fat_chain = !EXFAT_IS_ROOT(dp->node_dirclust,
	    dp->node_diroffset) &&
	    (dp->node_stream_flags & EXFAT_FLAG_NO_FAT_CHAIN) != 0;

	if (had_no_fat_chain && last_cn > first_cn) {
		error = exfat_fat_link_range(pmp, first_cn,
		    last_cn - first_cn, last_cn);
		if (error != 0) {
			(void)exfat_fat_clear_range(pmp, first_cn,
			    last_cn - first_cn);
			exfat_free_cluster_chain(pmp, first_new_cn,
			    false, 0);
			return (error);
		}
	}

	/* Link the last existing cluster to first_new_cn in the FAT. */
	if (EXFAT_CLUSTER_VALID(pmp, last_cn)) {
		error = exfat_fat_set(pmp, last_cn, first_new_cn);
		if (error != 0) {
			if (had_no_fat_chain && last_cn > first_cn)
				(void)exfat_fat_clear_range(pmp, first_cn,
				    last_cn - first_cn);
			exfat_free_cluster_chain(pmp, first_new_cn, false, 0);
			return (error);
		}
	} else
		dp->node_first_cluster = first_new_cn;

	/*
	 * Phase 4: Update directory metadata and commit to disk.
	 *
	 * For a non-root directory, update stream flags to set
	 * AllocationPossible and clear NoFatChain, increment node_size and
	 * node_valid_size, and sync the directory's Stream Extension entry
	 * via exfat_node_sync(). If syncing fails, undo the FAT links, free
	 * the new clusters, and restore original node metadata.
	 *
	 * Root directory size is tracked only in-memory (exFAT root directory
	 * does not have a Stream Extension dentry on disk).
	 */
	if (!EXFAT_IS_ROOT(dp->node_dirclust, dp->node_diroffset)) {
		uint32_t orig_flag = dp->node_flag;
		uint8_t orig_stream_flags = dp->node_stream_flags;

		dp->node_stream_flags = (dp->node_stream_flags |
		    EXFAT_FLAG_ALLOC_POSSIBLE) & ~EXFAT_FLAG_NO_FAT_CHAIN;
		dp->node_size += (uint64_t)needed_clusters *
		    pmp->pm_cluster_size;
		/*
		 * Newly allocated directory clusters are zeroed out as empty
		 * directory entry slots (0x00). Synchronize node_valid_size
		 * to node_size so directory lookups and readdir do not treat
		 * them as uninitialized sparse data, satisfying Spec §7.6.5.
		 */
		dp->node_valid_size = dp->node_size;
		dp->node_flag |= EXFAT_NODE_DIRTY;
		error = exfat_node_sync(dp);
		if (error != 0) {
			if (had_no_fat_chain &&
			    EXFAT_CLUSTER_VALID(pmp, last_cn)) {
				for (uint32_t r = first_cn; r <= last_cn; r++)
					(void)exfat_fat_set(pmp, r,
					    EXFAT_FAT_FREE);
				dp->node_stream_flags |=
				    EXFAT_FLAG_NO_FAT_CHAIN;
			} else if (EXFAT_CLUSTER_VALID(pmp, last_cn))
				(void)exfat_fat_set(pmp, last_cn,
				    EXFAT_FAT_EOF);
			else
				dp->node_first_cluster = 0;
			dp->node_stream_flags = orig_stream_flags;
			dp->node_flag = orig_flag;
			exfat_free_cluster_chain(pmp, first_new_cn, false, 0);
			dp->node_size -= (uint64_t)needed_clusters *
			    pmp->pm_cluster_size;
			dp->node_valid_size = dp->node_size;
			return (error);
		}
	} else {
		dp->node_size += (uint64_t)needed_clusters *
		    pmp->pm_cluster_size;
		dp->node_valid_size = dp->node_size;
	}

	/*
	 * Phase 5: Return the starting slot location and update hint cursor.
	 *
	 * If trailing free entries existed at the end of the previous cluster
	 * (run_len > 0), the allocated entry set begins at run_start_clust and
	 * run_start_offset, spanning across the cluster boundary into
	 * first_new_cn. Otherwise, the entry set begins at offset 0 of
	 * first_new_cn.
	 *
	 * Advance the hint cursor to the slot immediately following the new
	 * entry set so subsequent allocations continue from there.
	 */
	if (run_len > 0 && run_len < count) {
		*slot_clusterp = run_start_clust;
		*slot_offsetp = run_start_offset;
	} else {
		*slot_clusterp = first_new_cn;
		*slot_offsetp = 0;
	}
	dp->node_dir_hint_clust = last_new_cn;
	dp->node_dir_hint_offset = ((count - run_len - 1) %
	    entries_per_clust + 1) * sizeof(union exfat_dentry);
	return (0);
}

/*
 * Check whether directory dp is empty.
 *
 * Scans all directory entries using a directory cursor.  If any in-use entry
 * is found before EXFAT_ENTRY_EOD, returns ENOTEMPTY.
 *
 * Returns 0 if empty, ENOTEMPTY if any in-use entry exists, ENOTDIR if dp is
 * not a directory, EBUSY if dp is the root directory, or an I/O error.
 */
int
exfat_dir_is_empty(struct exfat_node *dp)
{
	struct exfat_mount *pmp;
	struct exfat_dir_cursor dc;
	const union exfat_dentry *dent;
	int error;

	if (dp == NULL || (dp->node_attributes & EXFAT_ATTR_DIRECTORY) == 0)
		return (ENOTDIR);
	if (EXFAT_IS_ROOT(dp->node_dirclust, dp->node_diroffset))
		return (EBUSY);

	pmp = dp->node_pmp;

	exfat_dir_cursor_init(pmp, dp, &dc);
	while (1) {
		error = exfat_dir_cursor_get(&dc, &dent, NULL, NULL);
		if (error != 0) {
			if (error == ENOENT)
				error = 0;
			break;
		}
		if (dent->type == EXFAT_ENTRY_EOD)
			break;
		if ((dent->type & EXFAT_ENTRY_TYPE_IN_USE) != 0) {
			error = ENOTEMPTY;
			break;
		}
		error = exfat_dir_cursor_next(&dc);
		if (error != 0)
			break;
	}
	exfat_dir_cursor_put(&dc);
	return (error);
}

/*
 * Shrink trailing empty clusters of a directory after an entry is removed.
 *
 * Scans directory dp to find the highest active (in-use) entry offset.  Per
 * exFAT Spec §7.6.7, a directory's size must be a multiple of the cluster
 * size.  If all entries in trailing clusters are unused or deleted, truncates
 * trailing clusters beyond the first cluster to reclaim cluster heap space.
 *
 * Returns 0 on success (or if no shrink was possible), ENOTDIR if dp is not
 * a directory, or an error code from truncation or metadata sync.
 */
int
exfat_dir_shrink(struct exfat_node *dp)
{
	struct exfat_mount *pmp;
	struct exfat_dir_cursor dc;
	const union exfat_dentry *dent;
	uint32_t cluster_size;
	uint64_t last_active_end = 0;
	uint64_t new_size;
	uint64_t cur_offset;
	int error;

	if (dp == NULL || (dp->node_attributes & EXFAT_ATTR_DIRECTORY) == 0)
		return (ENOTDIR);

	pmp = dp->node_pmp;
	cluster_size = pmp->pm_cluster_size;

	/*
	 * Cannot shrink a directory that already occupies 1 cluster or less,
	 * or has no valid cluster allocation.
	 */
	if (dp->node_size <= cluster_size ||
	    dp->node_first_cluster == 0 ||
	    !EXFAT_CLUSTER_VALID(pmp, dp->node_first_cluster))
		return (0);

	exfat_dir_cursor_init(pmp, dp, &dc);
	while (1) {
		error = exfat_dir_cursor_get(&dc, &dent, NULL, NULL);
		if (error != 0)
			break;

		if (dent->type == EXFAT_ENTRY_EOD)
			break;

		if ((dent->type & EXFAT_ENTRY_TYPE_IN_USE) != 0) {
			cur_offset = (uint64_t)dc.dc_clusters_read *
			    cluster_size + dc.dc_offset;
			if (dent->type == EXFAT_ENTRY_FILE &&
			    dent->file.fe_secondary_count <=
			    EXFAT_MAX_SECONDARY_COUNT) {
				uint8_t sec_cnt =
				    dent->file.fe_secondary_count;

				last_active_end = cur_offset +
				    (uint64_t)(1 + sec_cnt) *
				    sizeof(union exfat_dentry);
				error = exfat_dir_cursor_skip(&dc, sec_cnt);
				if (error != 0)
					break;
			} else
				last_active_end = cur_offset +
				    sizeof(union exfat_dentry);
		}

		error = exfat_dir_cursor_next(&dc);
		if (error != 0)
			break;
	}
	exfat_dir_cursor_put(&dc);

	if (error != 0 && error != ENOENT)
		return (error);

	new_size = roundup2(last_active_end, cluster_size);
	if (new_size < cluster_size)
		new_size = cluster_size;

	if (new_size >= dp->node_size)
		return (0);

	/*
	 * Truncate trailing directory clusters.
	 */
	error = exfat_truncate(dp, new_size);
	if (error != 0)
		return (error);

	/*
	 * Reset hint because trailing clusters were truncated.
	 */
	dp->node_dir_hint_clust = dp->node_first_cluster;
	dp->node_dir_hint_offset = 0;

	/*
	 * Update parent directory stream entry (if not root).
	 */
	if (!EXFAT_IS_ROOT(dp->node_dirclust, dp->node_diroffset)) {
		dp->node_flag |= EXFAT_NODE_DIRTY;
		return (exfat_node_sync(dp));
	}

	return (0);
}
