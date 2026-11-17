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
#include <sys/lockmgr.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vnode_pager.h>

#include <fs/exfat/exfat_fat.h>
#include <fs/exfat/exfat_lookup.h>
#include <fs/exfat/exfat_node.h>
#include <fs/exfat/exfat_ondisk.h>
#include <fs/exfat/exfat_subr.h>
#include <fs/exfat/exfat_vfsops.h>
#include <fs/exfat/exfat_vnops.h>

MALLOC_DEFINE(M_EXFATNODE, "exfat_node", "EXFAT node structure");

/*
 * Vnode hash comparator callback for vfs_hash.
 *
 * Compares vnode vp's synthetic inode number against the target inode
 * number passed in arg.  Excludes unlinked nodes (EXFAT_NODE_UNLINKED) so
 * that unlinked files awaiting deferred reclamation are not matched.
 *
 * Returns 0 on match (equal), or non-zero on mismatch.
 */
int
exfat_vncmpf(struct vnode *vp, void *arg)
{
	struct exfat_node *np;
	uint64_t *a;

	a = arg;
	np = VTONODE(vp);
	return (np->node_inode != *a ||
	    (np->node_flag & EXFAT_NODE_UNLINKED) != 0);
}

/*
 * Generate a unique 64-bit inode number from directory cluster and offset.
 *
 * For the root directory (represented by sentinel dirclust 0 and diroffset 0),
 * return the traditional UNIX root inode number 2 (ROOTINO).  Returning 0
 * is forbidden because inode 0 is reserved in POSIX/BSD VFS to denote an
 * invalid or unallocated entry.  Because real cluster heap allocations always
 * start at EXFAT_FIRST_CLUSTER (cluster 2), all non-root nodes have
 * dirclust >= 2 and their synthesized inode number is at least (2ULL << 32)
 * (approx. 8.5 billion), guaranteeing that non-root inodes never collide
 * with inode 2.
 *
 * Returns the synthetic 64-bit inode number (st_ino).
 */
uint64_t
exfat_make_inode(uint32_t dirclust, uint32_t diroffset)
{
	if (EXFAT_IS_ROOT(dirclust, diroffset))
		return (2);	/* ROOTINO */

	return (((uint64_t)dirclust << 32) | diroffset);
}

/*
 * Load and validate directory entry metadata from disk for an exFAT node.
 *
 * Reads the entry set using exfat_dentry_read_set() and unpacks file
 * attributes, timestamps, stream extension fields (first cluster, DataLength,
 * ValidDataLength, stream flags), and secondary entry counts.  Validates
 * allocation constraints and directory size limits per exFAT Spec §7.6.6 and
 * §7.6.7, and initializes the vnode type (VDIR or VREG).
 *
 * Returns 0 on success, EINVAL if metadata is corrupt or invalid, or an I/O
 * error.
 */
static int
exfat_node_load(struct exfat_node *np)
{
	struct exfat_mount *pmp;
	union exfat_dentry dent[EXFAT_MAX_ENTRY_SET];
	const struct exfat_dentry_file *fe;
	const struct exfat_dentry_stream *stream;
	int error;

	if (np == NULL || np->node_pmp == NULL)
		return (EINVAL);

	pmp = np->node_pmp;

	/*
	 * Root directory has no parent directory entry set.
	 */
	if (EXFAT_IS_ROOT(np->node_dirclust, np->node_diroffset))
		return (0);

	error = exfat_dentry_read_set(pmp, NULL, np->node_dirclust,
	    np->node_diroffset, dent, NULL);
	if (error != 0)
		return (error);

	fe = &dent[0].file;
	stream = &dent[1].stream;

	/* Populate node attributes and entry set metadata */
	np->node_attributes = le16toh(fe->fe_file_attributes);
	np->node_secondary_count = fe->fe_secondary_count;

	/* Timestamps */
	np->node_ctime = le32toh(fe->fe_create_timestamp);
	np->node_mtime = le32toh(fe->fe_last_modified_timestamp);
	np->node_atime = le32toh(fe->fe_last_access_timestamp);
	np->node_c_10ms = fe->fe_create_10ms_increment;
	np->node_m_10ms = fe->fe_last_modified_10ms_increment;
	np->node_c_tz = fe->fe_create_tz_offset;
	np->node_m_tz = fe->fe_last_modified_tz_offset;
	np->node_a_tz = fe->fe_last_access_tz_offset;

	/* Stream extension fields */
	np->node_stream_flags = stream->se_general_flags;
	np->node_first_cluster = le32toh(stream->se_first_cluster);
	np->node_size = le64toh(stream->se_data_length);
	np->node_valid_size = le64toh(stream->se_valid_data_length);

	/*
	 * Validate ValidDataLength per exFAT Spec §7.6.5. ValidDataLength may
	 * be less than or equal to DataLength. If ValidDataLength exceeds
	 * DataLength, the entry is corrupt and must be rejected.
	 *
	 * For directories, Spec §7.6.5 states that ValidDataLength shall equal
	 * DataLength. However, the spec does not define ValidDataLength <
	 * DataLength as an error condition requiring mount or node rejection.
	 * In-memory node_valid_size is clamped to node_size for directories
	 * so directory lookups, scans, and page-ins treat all allocated
	 * clusters as valid directory entry space (preventing synthetic
	 * zeroes from masking directory entries), while gracefully tolerating
	 * volumes produced by non-conforming formatters or tools. In-memory
	 * clamping does not alter on-disk directory entries or checksums.
	 */
	if (np->node_valid_size > np->node_size)
		return (EINVAL);
	if ((np->node_attributes & EXFAT_ATTR_DIRECTORY) != 0)
		np->node_valid_size = np->node_size;

	/*
	 * Validate GeneralSecondaryFlags per exFAT Spec §7.6.2:
	 * - AllocationPossible (bit 0) valid value is 1 (Spec §7.6.2.1).
	 * - CustomDefined bits (bits 7:2) shall conform to 0
	 *   (Spec §7.6.2 and §6.4.2.3).
	 */
	if ((np->node_stream_flags & EXFAT_FLAG_ALLOC_POSSIBLE) == 0 ||
	    (np->node_stream_flags & ~(EXFAT_FLAG_ALLOC_POSSIBLE |
	    EXFAT_FLAG_NO_FAT_CHAIN)) != 0)
		return (EINVAL);

	/*
	 * Validate allocation and first cluster per exFAT Spec §7.6.6 and
	 * §7.6.7.  A directory's DataLength is the size of its allocation,
	 * which may be 0, at most 256MB, and a multiple of cluster size.
	 * If FirstCluster is 0, no cluster allocation exists and DataLength
	 * must be 0 (Spec §7.6.7).  If FirstCluster is non-zero, it must
	 * lie within the cluster heap.
	 */
	if ((np->node_attributes & EXFAT_ATTR_DIRECTORY) != 0 &&
	    np->node_size > EXFAT_MAX_DIR_SIZE)
		return (EINVAL);
	if (np->node_first_cluster == 0) {
		if (np->node_size != 0)
			return (EINVAL);
	} else if (!EXFAT_CLUSTER_VALID(pmp, np->node_first_cluster))
		return (EINVAL);

	if (UINT64_MAX - np->node_size < pmp->pm_cluster_mask ||
	    howmany(np->node_size, pmp->pm_cluster_size) >
	    pmp->pm_cluster_count)
		return (EINVAL);
	if (np->node_size > 0 &&
	    (np->node_stream_flags & EXFAT_FLAG_NO_FAT_CHAIN) != 0 &&
	    howmany(np->node_size, pmp->pm_cluster_size) >
	    pmp->pm_cluster_count - EXFAT_CNTOI(np->node_first_cluster))
		return (EINVAL);

	/* Determine directory size if not provided */
	if ((np->node_attributes & EXFAT_ATTR_DIRECTORY) &&
	    np->node_size == 0 &&
	    EXFAT_CLUSTER_VALID(pmp, np->node_first_cluster)) {
		if (np->node_stream_flags & EXFAT_FLAG_NO_FAT_CHAIN)
			np->node_size = pmp->pm_cluster_size;
		else {
			uint32_t cn = np->node_first_cluster;
			uint32_t count = 0;

			while (EXFAT_CLUSTER_VALID(pmp, cn) &&
			    count < pmp->pm_cluster_count) {
				count++;
				if (exfat_fat_get(pmp, cn, &cn) != 0)
					break;
			}
			np->node_size = (uint64_t)count * pmp->pm_cluster_size;
		}
	}

	/*
	 * Determine directory size if not provided, and enforce directory
	 * invariants per Spec §7.6.7. If directory size was determined from
	 * a FAT chain walk, clamp node_size to EXFAT_MAX_DIR_SIZE (256MB)
	 * so corrupt or cyclic FAT chains cannot allocate an oversized
	 * directory structure in kernel memory. Round up to cluster boundary
	 * and clamp node_valid_size to node_size so all allocated clusters
	 * are treated as valid directory space.
	 */
	if (np->node_attributes & EXFAT_ATTR_DIRECTORY) {
		if (np->node_size > EXFAT_MAX_DIR_SIZE)
			np->node_size = EXFAT_MAX_DIR_SIZE;
		if (np->node_size > 0 &&
		    (np->node_size % pmp->pm_cluster_size) != 0)
			np->node_size = roundup2(np->node_size,
			    pmp->pm_cluster_size);
		np->node_valid_size = np->node_size;
	}

	if (np->node_vnode != NULL) {
		if (np->node_attributes & EXFAT_ATTR_DIRECTORY) {
			np->node_vnode->v_type = VDIR;
			np->node_dir_hint_clust = np->node_first_cluster;
			np->node_dir_hint_offset = 0;
		} else
			np->node_vnode->v_type = VREG;
	}

	return (0);
}

/*
 * Look up or allocate a vnode and exfat_node for a given directory entry set.
 *
 * Queries vfs_hash_get() for the inode corresponding to (dirclust, diroffset).
 * If already cached, returns the locked node.  Otherwise, allocates a new
 * struct exfat_node and vnode, locks the vnode exclusively (exFAT vnodes do
 * not opt into VN_LOCK_ASHARE), initializes cluster write caching and hint
 * cursors, inserts into vfs_hash, loads on-disk metadata via
 * exfat_node_load(), and transitions the vnode to VSTATE_CONSTRUCTED.
 *
 * Stores the locked node in *nodepp on success.
 * Returns 0 on success, or an error code from vfs_hash or disk I/O.
 */
int
exfat_node_get(struct exfat_mount *pmp, uint32_t dirclust, uint32_t diroffset,
    int lkflags, struct exfat_node **nodepp)
{
	struct mount *mntp;
	struct vnode *nvp, *xvp;
	struct exfat_node *np;
	uint64_t inode;
	int error, i;

	mntp = pmp->pm_mountp;
	inode = exfat_make_inode(dirclust, diroffset);

	/*
	 * Exfat vnodes do not opt into shared locking (VN_LOCK_ASHARE);
	 * enforce exclusive lock acquisition on in-memory node lookup.
	 */
	lkflags = (lkflags & ~LK_TYPE_MASK) | LK_EXCLUSIVE;

	error = vfs_hash_get(mntp, exfat_vnode_hash(inode), lkflags,
	    curthread, &nvp, exfat_vncmpf, &inode);
	if (error != 0)
		return (error);
	if (nvp != NULL) {
		*nodepp = VTONODE(nvp);
		return (0);
	}

	np = malloc(sizeof(*np), M_EXFATNODE, M_WAITOK | M_ZERO);

	error = getnewvnode("exfat", mntp, &exfat_vnodeops, &nvp);
	if (error != 0) {
		free(np, M_EXFATNODE);
		*nodepp = NULL;
		return (error);
	}

	nvp->v_data = np;
	np->node_vnode = nvp;
	np->node_pmp = pmp;
	np->node_dirclust = dirclust;
	np->node_diroffset = diroffset;
	np->node_inode = inode;

	cluster_init_vn(&np->node_clusterw);

	for (i = 0; i < EXFAT_FC_SIZE; i++) {
		np->node_fc[i].fc_frcn = EXFAT_FCE_EMPTY;
		np->node_fc[i].fc_fsrcn = EXFAT_FCE_EMPTY;
	}

	/*
	 * Lock the newly allocated vnode exclusively.  Do not pass
	 * LK_NOWITNESS so WITNESS properly tracks lock acquisition on new
	 * vnodes when returned to callers.
	 */
	lockmgr(nvp->v_vnlock, LK_EXCLUSIVE, NULL);

	if (EXFAT_IS_ROOT(dirclust, diroffset)) {
		struct exfat_fat_cursor fc;
		uint32_t rcn = pmp->pm_rootdir_cluster;
		uint32_t rcount = 0;

		nvp->v_type = VDIR;
		nvp->v_vflag |= VV_ROOT;
		np->node_attributes = EXFAT_ATTR_DIRECTORY;
		np->node_first_cluster = pmp->pm_rootdir_cluster;
		np->node_dir_hint_clust = pmp->pm_rootdir_cluster;
		np->node_dir_hint_offset = 0;
		np->node_parent_dirclust = EXFAT_ROOT_DIRCLUST;
		np->node_parent_diroffset = EXFAT_ROOT_DIROFFSET;

		exfat_fat_cursor_init(pmp, &fc);
		while (EXFAT_CLUSTER_VALID(pmp, rcn) &&
		    rcount < pmp->pm_cluster_count) {
			rcount++;
			if (exfat_fat_cursor_get(&fc, rcn, &rcn) != 0)
				break;
		}
		exfat_fat_cursor_put(&fc);
		np->node_size = (uint64_t)rcount * pmp->pm_cluster_size;
		/*
		 * The root directory has no on-disk Stream Extension entry,
		 * but in-memory operations require node_valid_size == node_size
		 * so all root clusters are treated as valid directory space.
		 */
		np->node_valid_size = np->node_size;
	}

	error = insmntque(nvp, mntp);
	if (error != 0) {
		free(np, M_EXFATNODE);
		*nodepp = NULL;
		return (error);
	}

	error = vfs_hash_insert(nvp, exfat_vnode_hash(inode), lkflags,
	    curthread, &xvp, exfat_vncmpf, &inode);
	if (error != 0) {
		*nodepp = NULL;
		return (error);
	}
	if (xvp != NULL) {
		*nodepp = VTONODE(xvp);
		return (0);
	}

	if (!EXFAT_IS_ROOT(dirclust, diroffset)) {
		error = exfat_node_load(np);
		if (error != 0) {
			vgone(nvp);
			vput(nvp);
			*nodepp = NULL;
			return (error);
		}
	}

	vn_set_state(nvp, VSTATE_CONSTRUCTED);
	*nodepp = np;
	return (0);
}

/*
 * Free an in-memory exfat_node.
 *
 * Releases memory allocated for np from the M_EXFATNODE malloc pool.
 * Called when the associated vnode is reclaimed.
 */
void
exfat_node_free(struct exfat_node *np)
{
	if (np == NULL)
		return;
	free(np, M_EXFATNODE);
}

/*
 * Update modification and access timestamps on node np if pending.
 *
 * Checks EXFAT_NODE_MTIME and EXFAT_NODE_ATIME flags.  When set, samples the
 * current system timestamp with vfs_timestamp(), converts to MS-DOS packed
 * date/time and timezone offset, updates node_mtime / node_atime, dirties
 * the node (EXFAT_NODE_DIRTY), and clears pending timestamp flags.
 */
void
exfat_times(struct exfat_node *np)
{
	struct timespec ts;
	uint16_t date, time;
	uint8_t hun;
	uint8_t tz;

	if ((np->node_flag & (EXFAT_NODE_MTIME | EXFAT_NODE_ATIME)) == 0)
		return;

	tz = exfat_tz_offset();
	vfs_timestamp(&ts);
	timespec2fattime(&ts, 0, &date, &time, &hun);
	if (np->node_flag & EXFAT_NODE_MTIME) {
		np->node_mtime = ((uint32_t)date << 16) | time;
		np->node_m_10ms = hun;
		np->node_m_tz = tz;
		if (np->node_pmp == NULL || np->node_pmp->pm_mountp == NULL ||
		    (np->node_pmp->pm_mountp->mnt_flag & MNT_NOATIME) == 0) {
			np->node_atime = np->node_mtime;
			np->node_a_tz = tz;
		}
		np->node_flag |= EXFAT_NODE_DIRTY;
		np->node_flag &= ~(EXFAT_NODE_MTIME | EXFAT_NODE_ATIME);
	} else if (np->node_flag & EXFAT_NODE_ATIME) {
		np->node_atime = ((uint32_t)date << 16) | time;
		np->node_a_tz = tz;
		np->node_flag |= EXFAT_NODE_DIRTY;
		np->node_flag &= ~EXFAT_NODE_ATIME;
	}
}

/*
 * Sync in-memory node metadata changes back to the on-disk directory entry
 * set.
 *
 * Checks if np has pending metadata or timestamp updates.  If dirty, reads the
 * directory entry set via exfat_dentry_read_set(), flushes timestamps with
 * exfat_times(), updates file attributes and stream extension fields
 * (first cluster, DataLength, ValidDataLength, stream flags), recalculates
 * the entry set checksum per Spec §6.3.3 / §7.4.3, and writes the set back
 * using exfat_dentry_write_set().
 *
 * Returns 0 on success (or if no sync was needed), or an I/O error from
 * directory entry access.
 */
int
exfat_node_sync(struct exfat_node *np)
{
	struct exfat_mount *pmp;
	union exfat_dentry dent[EXFAT_MAX_ENTRY_SET];
	uint64_t valid_len;
	uint8_t count;
	int error;

	if (np == NULL)
		return (0);

	if ((np->node_flag & (EXFAT_NODE_MTIME | EXFAT_NODE_ATIME |
	    EXFAT_NODE_DIRTY)) == 0)
		return (0);

	/* If unlinked, the directory entry set on disk has been deleted */
	if (np->node_flag & EXFAT_NODE_UNLINKED) {
		np->node_flag &= ~(EXFAT_NODE_MTIME | EXFAT_NODE_ATIME |
		    EXFAT_NODE_DIRTY);
		return (0);
	}

	pmp = np->node_pmp;

	if ((pmp->pm_flags & EXFAT_MNT_RONLY) != 0) {
		np->node_flag &= ~(EXFAT_NODE_MTIME | EXFAT_NODE_ATIME |
		    EXFAT_NODE_DIRTY);
		return (0);
	}

	/* Root directory has no parent directory entry set */
	if (EXFAT_IS_ROOT(np->node_dirclust, np->node_diroffset)) {
		np->node_flag &= ~(EXFAT_NODE_MTIME | EXFAT_NODE_ATIME |
		    EXFAT_NODE_DIRTY);
		return (0);
	}

	error = exfat_dentry_read_set(pmp, NULL, np->node_dirclust,
	    np->node_diroffset, dent, &count);
	if (error != 0)
		return (error);

	/* Update timestamps */
	exfat_times(np);

	dent[0].file.fe_file_attributes = htole16(np->node_attributes);
	dent[0].file.fe_create_timestamp = htole32(np->node_ctime);
	dent[0].file.fe_create_10ms_increment = np->node_c_10ms;
	dent[0].file.fe_create_tz_offset = np->node_c_tz;
	dent[0].file.fe_last_modified_timestamp = htole32(np->node_mtime);
	dent[0].file.fe_last_modified_10ms_increment = np->node_m_10ms;
	dent[0].file.fe_last_modified_tz_offset = np->node_m_tz;
	dent[0].file.fe_last_access_timestamp = htole32(np->node_atime);
	dent[0].file.fe_last_access_tz_offset = np->node_a_tz;

	/* Update stream entry */
	np->node_stream_flags |= EXFAT_FLAG_ALLOC_POSSIBLE;
	if (!EXFAT_CLUSTER_VALID(pmp, np->node_first_cluster))
		np->node_stream_flags &= ~EXFAT_FLAG_NO_FAT_CHAIN;
	dent[1].stream.se_general_flags = np->node_stream_flags;
	dent[1].stream.se_first_cluster = htole32(np->node_first_cluster);
	dent[1].stream.se_data_length = htole64(np->node_size);
	/*
	 * Per Spec §7.6.5, ValidDataLength shall equal DataLength for a
	 * directory, and shall not exceed DataLength for a regular file.
	 * Defensively clamp valid_len to node_size when writing to disk
	 * so the on-disk Stream Extension entry strictly complies with
	 * §7.6.5 regardless of in-memory fluctuations. The directory entry
	 * set checksum is recalculated immediately below over these fields.
	 */
	if ((np->node_attributes & EXFAT_ATTR_DIRECTORY) != 0 ||
	    np->node_valid_size > np->node_size)
		valid_len = np->node_size;
	else
		valid_len = np->node_valid_size;
	dent[1].stream.se_valid_data_length = htole64(valid_len);

	/* Recalculate directory entry set checksum */
	exfat_dentry_set_checksum(dent, count);

	error = exfat_dentry_write_set(pmp, NULL, np->node_dirclust,
	    np->node_diroffset, dent, count);
	if (error != 0)
		return (error);

	np->node_flag &= ~(EXFAT_NODE_MTIME | EXFAT_NODE_ATIME |
	    EXFAT_NODE_DIRTY);
	return (0);
}

/*
 * Traverse the FAT chain starting at start_cn to locate the terminal cluster.
 *
 * Queries the FAT entry for each cluster until EXFAT_FAT_EOF is encountered.
 * Validates cluster validity and checks against infinite cycles.  If
 * expected_clusters > 0, verifies that the traversed chain length exactly
 * matches expected_clusters.
 *
 * Stores the last cluster number in *last_cnp.
 * Returns 0 on success, EIO on invalid cluster or length mismatch, ELOOP on
 * cycle detection, or an I/O error from FAT access.
 */
static int
exfat_find_chain_end(struct exfat_mount *pmp, uint32_t start_cn,
    uint32_t expected_clusters, uint32_t *last_cnp)
{
	struct exfat_fat_cursor fc;
	uint32_t cn = start_cn, next_cn, walked = 0;
	int error;

	exfat_fat_cursor_init(pmp, &fc);
	for (;;) {
		error = exfat_fat_cursor_get(&fc, cn, &next_cn);
		if (error != 0) {
			exfat_fat_cursor_put(&fc);
			return (error);
		}
		if (EXFAT_FAT_IS_EOF(next_cn))
			break;
		if (!EXFAT_CLUSTER_VALID(pmp, next_cn)) {
			exfat_fat_cursor_put(&fc);
			return (EIO);
		}
		if (++walked > pmp->pm_cluster_count) {
			exfat_fat_cursor_put(&fc);
			return (ELOOP);
		}
		cn = next_cn;
	}
	exfat_fat_cursor_put(&fc);
	if (expected_clusters > 0 && walked + 1 != expected_clusters)
		return (EIO);
	*last_cnp = cn;
	return (0);
}

/*
 * Extend a file's cluster allocation to cover target_size bytes.
 *
 * Validates target_size against volume bounds.  If additional clusters are
 * required, allocates them from the allocation bitmap.  If the file was
 * previously contiguous but the new allocation is fragmented (or vice versa),
 * converts the existing contiguous run to an explicit FAT chain by linking
 * clusters in the FAT.  Links the new clusters to the end of the chain,
 * terminates with EXFAT_FAT_EOF, updates node_size, resizes the VM vnode
 * pager, and marks the node dirty.
 *
 * Returns 0 on success, EFBIG if target_size exceeds volume capacity,
 * ENOSPC if insufficient free clusters exist, or an I/O error.
 */
int
exfat_extend_file(struct exfat_node *np, uint64_t target_size)
{
	struct exfat_mount *pmp = np->node_pmp;
	uint64_t new_clusters_64, old_clusters_64;
	uint32_t needed, new_clusters, old_clusters;
	int error;

	/*
	 * Phase 1: Parameter validation and cluster count calculations.
	 *
	 * Validate maximum file size and cluster count bounds. Clamp
	 * old_clusters to 1 if clusters are allocated while size is 0 to avoid
	 * arithmetic underflow on corrupt media (Spec Section 7.6.6 & 7.6.7).
	 * Enforce maximum directory size (256MB) and cluster alignment for
	 * directories per Spec §7.6.7.
	 * If new_clusters <= old_clusters, the file already has sufficient
	 * clusters; simply update node_size and return.
	 */
	if ((np->node_attributes & EXFAT_ATTR_DIRECTORY) != 0) {
		if (target_size > EXFAT_MAX_DIR_SIZE)
			return (EFBIG);
		if ((target_size & pmp->pm_cluster_mask) != 0)
			return (EINVAL);
	}

	if (target_size > (uint64_t)pmp->pm_cluster_count *
	    pmp->pm_cluster_size ||
	    UINT64_MAX - target_size < pmp->pm_cluster_mask)
		return (EFBIG);

	if (UINT64_MAX - np->node_size < pmp->pm_cluster_mask)
		return (EIO);
	old_clusters_64 = howmany(np->node_size, pmp->pm_cluster_size);
	new_clusters_64 = howmany(target_size, pmp->pm_cluster_size);
	if (old_clusters_64 > pmp->pm_cluster_count)
		return (EIO);
	if (new_clusters_64 > pmp->pm_cluster_count)
		return (EFBIG);

	old_clusters = (uint32_t)old_clusters_64;
	new_clusters = (uint32_t)new_clusters_64;

	/*
	 * On a fully conforming, uncorrupted volume, a 0-byte file must have
	 * node_first_cluster == 0 (spec 7.6.6 & 7.6.7).  Having clusters
	 * allocated while size is 0 is technically invalid and should never
	 * occur, but clamp old_clusters to 1 defensively to avoid underflow
	 * in (first_cn + old_clusters - 1) on corrupt or non-compliant media.
	 */
	if (EXFAT_CLUSTER_VALID(pmp, np->node_first_cluster) &&
	    old_clusters == 0)
		old_clusters = 1;

	if (new_clusters <= old_clusters) {
		np->node_size = target_size;
		/*
		 * Directory extensions allocate formatted entry space; keep
		 * node_valid_size in sync with node_size (Spec §7.6.5).
		 */
		if ((np->node_attributes & EXFAT_ATTR_DIRECTORY) != 0)
			np->node_valid_size = target_size;
		vnode_pager_setsize(NODETOV(np), target_size);
		np->node_flag |= EXFAT_NODE_DIRTY;
		return (0);
	}

	needed = new_clusters - old_clusters;

	if (!EXFAT_CLUSTER_VALID(pmp, np->node_first_cluster)) {
		/*
		 * Phase 2-1: Initial cluster allocation for an empty file.
		 *
		 * Allocate 'needed' clusters from the bitmap. If contiguous,
		 * set AllocationPossible and NoFatChain in Stream Extension
		 * flags (Spec Section 7.6.2 / 6.4.2); otherwise, trace chain
		 * tail and keep NoFatChain cleared.
		 */
		uint32_t start_cn;
		bool contig;

		error = exfat_bitmap_alloc_clusters(pmp, needed, &start_cn,
		    &contig);
		if (error != 0)
			return (error);

		np->node_first_cluster = start_cn;
		np->node_fc[EXFAT_FC_LASTMAP].fc_frcn = EXFAT_FCE_EMPTY;
		if (contig) {
			np->node_stream_flags =
			    EXFAT_FLAG_ALLOC_POSSIBLE | EXFAT_FLAG_NO_FAT_CHAIN;
			np->node_fc[EXFAT_FC_LASTFC].fc_frcn = new_clusters - 1;
			np->node_fc[EXFAT_FC_LASTFC].fc_fsrcn =
			    start_cn + needed - 1;
		} else {
			uint32_t walk_cn;

			np->node_stream_flags = EXFAT_FLAG_ALLOC_POSSIBLE;
			error = exfat_find_chain_end(pmp, start_cn, needed,
			    &walk_cn);
			if (error != 0) {
				exfat_free_cluster_chain(pmp, start_cn, false,
				    0);
				np->node_first_cluster = 0;
				return (error);
			}
			np->node_fc[EXFAT_FC_LASTFC].fc_frcn = new_clusters - 1;
			np->node_fc[EXFAT_FC_LASTFC].fc_fsrcn = walk_cn;
		}
	} else if (np->node_stream_flags & EXFAT_FLAG_NO_FAT_CHAIN) {
		/*
		 * Phase 2-2: Extension of a contiguous (NoFatChain) stream.
		 *
		 * Attempt to allocate contiguous clusters directly adjoining
		 * the current tail. If adjoining allocation succeeds, the
		 * stream remains contiguous.
		 *
		 * If adjoining allocation fails, convert the existing
		 * contiguous run into a FAT chain via exfat_fat_link_range(),
		 * clear NoFatChain (Spec Section 7.6.2 / 6.4.2), and allocate
		 * remaining clusters in chunked batches, linking each chunk
		 * into the FAT.
		 */
		uint32_t first_cn = np->node_first_cluster;
		uint32_t last_cn;

		if (!EXFAT_CLUSTER_VALID(pmp, first_cn) ||
		    UINT32_MAX - first_cn < old_clusters)
			return (EIO);

		last_cn = first_cn + old_clusters - 1;
		if (last_cn < UINT32_MAX &&
		    exfat_bitmap_alloc_contiguous_at(pmp, last_cn + 1,
		    needed) == 0) {
			/* Success! Still contiguous. */
			np->node_fc[EXFAT_FC_LASTFC].fc_frcn = new_clusters - 1;
			np->node_fc[EXFAT_FC_LASTFC].fc_fsrcn =
			    last_cn + needed;
		} else {
			/*
			 * Could not extend contiguously. Convert existing
			 * contiguous run into a FAT chain.
			 */
			uint32_t first_new_cn, prev_cn, remaining;

			error = exfat_fat_link_range(pmp, first_cn,
			    last_cn - first_cn + 1, EXFAT_FAT_EOF);
			if (error != 0) {
				(void)exfat_fat_clear_range(pmp, first_cn,
				    last_cn - first_cn + 1);
				return (error);
			}
			np->node_stream_flags &= ~EXFAT_FLAG_NO_FAT_CHAIN;
			np->node_fc[EXFAT_FC_LASTMAP].fc_frcn = EXFAT_FCE_EMPTY;

			/* Allocate new clusters in batches and chain them */
			prev_cn = last_cn;
			remaining = needed;
			first_new_cn = 0;

			while (remaining > 0) {
				uint32_t chunk = remaining;
				uint32_t new_cn;
				bool contig;

				error = exfat_bitmap_alloc_clusters(pmp, chunk,
				    &new_cn, &contig);
				if (error != 0) {
					error =
					    exfat_bitmap_alloc_clusters(pmp, 1,
					    &new_cn, &contig);
					if (error != 0)
						break;
					chunk = 1;
				}

				if (contig) {
					error = exfat_fat_link_range(pmp,
					    new_cn, chunk, EXFAT_FAT_EOF);
					if (error != 0) {
						(void)exfat_fat_clear_range(pmp,
						    new_cn, chunk);
						exfat_bitmap_free_clusters(pmp,
						    new_cn, chunk);
						break;
					}
				}

				error = exfat_fat_set(pmp, prev_cn, new_cn);
				if (error != 0) {
					exfat_free_cluster_chain(pmp, new_cn,
					    false, 0);
					break;
				}
				if (first_new_cn == 0)
					first_new_cn = new_cn;

				if (contig)
					prev_cn = new_cn + chunk - 1;
				else {
					error = exfat_find_chain_end(pmp,
					    new_cn, chunk, &prev_cn);
					if (error != 0)
						break;
				}

				remaining -= chunk;
			}
			if (error != 0) {
				if (first_new_cn != 0)
					exfat_free_cluster_chain(pmp,
					    first_new_cn, false, 0);
				(void)exfat_fat_clear_range(pmp, first_cn,
				    last_cn - first_cn + 1);
				np->node_stream_flags |=
				    EXFAT_FLAG_NO_FAT_CHAIN;
				return (error);
			}

			np->node_fc[EXFAT_FC_LASTFC].fc_frcn = new_clusters - 1;
			np->node_fc[EXFAT_FC_LASTFC].fc_fsrcn = prev_cn;
		}
	} else {
		/*
		 * Phase 2-3: Extension of an existing FAT-chained stream.
		 *
		 * Locate the terminal cluster of the existing chain (using the
		 * LASTFC flowcache hint or by traversing the FAT), allocate
		 * additional clusters in chunked batches from the bitmap, and
		 * append them to the FAT chain with rollback on error.
		 */
		uint32_t first_new_cn, last_cn, prev_cn, remaining;

		if (np->node_fc[EXFAT_FC_LASTFC].fc_frcn != EXFAT_FCE_EMPTY &&
		    np->node_fc[EXFAT_FC_LASTFC].fc_frcn == old_clusters - 1 &&
		    EXFAT_CLUSTER_VALID(pmp,
		    np->node_fc[EXFAT_FC_LASTFC].fc_fsrcn))
			last_cn = np->node_fc[EXFAT_FC_LASTFC].fc_fsrcn;
		else {
			error = exfat_find_chain_end(pmp,
			    np->node_first_cluster, old_clusters, &last_cn);
			if (error != 0)
				return (error);
		}

		prev_cn = last_cn;
		remaining = needed;
		first_new_cn = 0;
		error = 0;

		while (remaining > 0) {
			uint32_t chunk = remaining;
			uint32_t new_cn;
			bool contig;

			error = exfat_bitmap_alloc_clusters(pmp, chunk,
			    &new_cn, &contig);
			if (error != 0) {
				error = exfat_bitmap_alloc_clusters(pmp, 1,
				    &new_cn, &contig);
				if (error != 0)
					break;
				chunk = 1;
			}

			if (contig) {
				error = exfat_fat_link_range(pmp, new_cn,
				    chunk, EXFAT_FAT_EOF);
				if (error != 0) {
					(void)exfat_fat_clear_range(pmp,
					    new_cn, chunk);
					exfat_bitmap_free_clusters(pmp, new_cn,
					    chunk);
					break;
				}
			}

			error = exfat_fat_set(pmp, prev_cn, new_cn);
			if (error != 0) {
				exfat_free_cluster_chain(pmp, new_cn, false, 0);
				break;
			}
			if (first_new_cn == 0)
				first_new_cn = new_cn;

			if (contig)
				prev_cn = new_cn + chunk - 1;
			else {
				error = exfat_find_chain_end(pmp, new_cn,
				    chunk, &prev_cn);
				if (error != 0)
					break;
			}

			remaining -= chunk;
		}
		if (error != 0) {
			(void)exfat_fat_set(pmp, last_cn, EXFAT_FAT_EOF);
			if (first_new_cn != 0)
				exfat_free_cluster_chain(pmp, first_new_cn,
				    false, 0);
			return (error);
		}

		np->node_fc[EXFAT_FC_LASTFC].fc_frcn = new_clusters - 1;
		np->node_fc[EXFAT_FC_LASTFC].fc_fsrcn = prev_cn;
	}

	/*
	 * Phase 3: Commit new file size.
	 *
	 * Update node_size, resize the VM vnode pager, and mark the node dirty.
	 * For directories, synchronize node_valid_size to target_size
	 * because all newly allocated clusters are zeroed/formatted
	 * directory entry space, maintaining the Spec §7.6.5 invariant
	 * (ValidDataLength == DataLength).
	 */
	np->node_size = target_size;
	if ((np->node_attributes & EXFAT_ATTR_DIRECTORY) != 0)
		np->node_valid_size = target_size;
	vnode_pager_setsize(NODETOV(np), target_size);
	np->node_flag |= EXFAT_NODE_DIRTY;
	return (0);
}

/*
 * Truncate or extend a file to length bytes.
 *
 * If length > node_size, delegates to exfat_extend_file().  If length <
 * node_size, sanitizes partial cluster tail data beyond length in the buffer
 * cache and storage media, invalidates trailing cached pages with vtruncbuf(),
 * frees trailing cluster allocations using exfat_free_cluster_chain(),
 * terminates the shortened FAT chain with EXFAT_FAT_EOF, resizes the VM vnode
 * pager, updates node_size and node_valid_size, and marks the node dirty.
 *
 * Returns 0 on success, or an error code from allocation, buffer I/O, or
 * chain freeing.
 */
int
exfat_truncate(struct exfat_node *np, uint64_t length)
{
	struct exfat_mount *pmp = np->node_pmp;
	uint64_t old_clusters_64;
	uint32_t new_clusters, old_clusters;
	int error, i;

	/*
	 * Phase 1: Boundary validation and size calculation.
	 *
	 * Enforce maximum directory size (256MB) and cluster alignment for
	 * directories per Spec §7.6.7.
	 * If lengthening, delegate immediately to exfat_extend_file().
	 * Otherwise compute cluster requirements and validate bounds.
	 */
	if ((np->node_attributes & EXFAT_ATTR_DIRECTORY) != 0) {
		if (length > EXFAT_MAX_DIR_SIZE)
			return (EFBIG);
		if ((length & pmp->pm_cluster_mask) != 0)
			return (EINVAL);
	}

	if (length > np->node_size)
		return (exfat_extend_file(np, length));

	if (UINT64_MAX - np->node_size < pmp->pm_cluster_mask)
		return (EIO);
	old_clusters_64 = howmany(np->node_size, pmp->pm_cluster_size);
	if (old_clusters_64 > pmp->pm_cluster_count)
		return (EIO);
	old_clusters = (uint32_t)old_clusters_64;
	if (EXFAT_CLUSTER_VALID(pmp, np->node_first_cluster) &&
	    old_clusters == 0)
		old_clusters = 1;
	if (old_clusters > 0) {
		if (!EXFAT_CLUSTER_VALID(pmp, np->node_first_cluster))
			return (EIO);
		if ((np->node_stream_flags & EXFAT_FLAG_NO_FAT_CHAIN) != 0 &&
		    old_clusters > pmp->pm_cluster_count -
		    EXFAT_CNTOI(np->node_first_cluster))
			return (EIO);
	}
	new_clusters = (uint32_t)howmany(length, pmp->pm_cluster_size);

	/*
	 * Phase 2: Buffer cache sanitization and page truncation.
	 *
	 * Zero the tail of the partial cluster boundary to prevent stale data
	 * exposure if the file is later extended, then invalidate trailing
	 * buffers with vtruncbuf().
	 */
	if (NODETOV(np) != NULL && length < np->node_size) {
		size_t boff = (size_t)(length & pmp->pm_cluster_mask);

		/*
		 * If the new length is not a multiple of the cluster size,
		 * zero the tail end of the new last cluster so that stale
		 * data beyond EOF is sanitized from the buffer cache and
		 * storage media in case the file is subsequently extended.
		 *
		 * When length < node_valid_size, we are truncating into
		 * initialized data, so bread() the cluster to preserve valid
		 * bytes before length, zero the tail, and bdwrite() it.
		 *
		 * Conversely, when length >= node_valid_size, the new EOF
		 * falls in the unwritten preallocated hole.  While
		 * exfat_read_iodone() guarantees that reads beyond
		 * node_valid_size return zeroes rather than raw media data,
		 * unconditionally calling bread() and bdwrite() here would
		 * write out those zeroes and cause exfat_strategy() to advance
		 * node_valid_size to length, unnecessarily materializing the
		 * preallocated hole and generating unnecessary disk I/O.
		 * Hence, only check if a buffer is already in core via
		 * getblk(..., GB_NOCREAT) and sanitize its tail without
		 * issuing disk I/O or dirtying it.
		 */
		if (boff != 0 &&
		    (np->node_attributes & EXFAT_ATTR_DIRECTORY) == 0) {
			daddr_t lbn = length / pmp->pm_cluster_size;
			struct buf *bp;

			if (length < np->node_valid_size) {
				error = bread(NODETOV(np), lbn,
				    pmp->pm_cluster_size, NOCRED, &bp);
				if (error != 0) {
					if (bp != NULL)
						brelse(bp);
					return (error);
				}
				error = exfat_buf_resolve_blkno(np, bp);
				if (error != 0) {
					if ((bp->b_flags & B_DELWRI) == 0)
						bp->b_flags |= B_INVAL |
						    B_RELBUF | B_NOCACHE;
					brelse(bp);
					return (error);
				}
				memset(bp->b_data + boff, 0,
				    pmp->pm_cluster_size - boff);
				bdwrite(bp);
			} else {
				bp = getblk(NODETOV(np), lbn,
				    pmp->pm_cluster_size, 0, 0, GB_NOCREAT);
				if (bp != NULL) {
					memset(bp->b_data + boff, 0,
					    pmp->pm_cluster_size - boff);
					brelse(bp);
				}
			}
		}
		vtruncbuf(NODETOV(np), length, pmp->pm_cluster_size);
	}

	/*
	 * Phase 3: Cluster deallocation and FAT chain truncation.
	 *
	 * Free excess clusters:
	 * - If truncated to 0, free entire chain and clear node_first_cluster.
	 * - If contiguous (NoFatChain per Spec Section 7.6.2 / 6.4.2), free
	 *   the trailing range directly from the allocation bitmap.
	 * - If FAT-chained, traverse to the new last cluster, write
	 *   EXFAT_FAT_EOF, and free the disconnected tail chain.
	 */
	if (new_clusters < old_clusters) {
		uint32_t last_cn = 0;

		if (new_clusters == 0) {
			exfat_free_cluster_chain(pmp, np->node_first_cluster,
			    (np->node_stream_flags &
			    EXFAT_FLAG_NO_FAT_CHAIN) != 0, np->node_size);
			np->node_first_cluster = 0;
			np->node_stream_flags = EXFAT_FLAG_ALLOC_POSSIBLE;
		} else if (np->node_stream_flags & EXFAT_FLAG_NO_FAT_CHAIN) {
			uint32_t free_start =
			    np->node_first_cluster + new_clusters;
			uint32_t free_count = old_clusters - new_clusters;

			exfat_bitmap_free_clusters(pmp, free_start, free_count);
			last_cn = np->node_first_cluster + new_clusters - 1;
		} else {
			struct exfat_fat_cursor fc;
			uint32_t next_cn = 0;
			uint32_t walked = 0;

			last_cn = np->node_first_cluster;
			exfat_fat_cursor_init(pmp, &fc);
			for (uint32_t c = 0; c < new_clusters - 1; c++) {
				if (++walked > pmp->pm_cluster_count) {
					exfat_fat_cursor_put(&fc);
					error = ELOOP;
					goto fat_err;
				}
				error = exfat_fat_cursor_get(&fc, last_cn,
				    &next_cn);
				if (error != 0) {
					exfat_fat_cursor_put(&fc);
					goto fat_err;
				}
				if (!EXFAT_CLUSTER_VALID(pmp, next_cn)) {
					exfat_fat_cursor_put(&fc);
					error = EIO;
					goto fat_err;
				}
				last_cn = next_cn;
			}
			error = exfat_fat_cursor_get(&fc, last_cn, &next_cn);
			exfat_fat_cursor_put(&fc);
			if (error != 0)
				goto fat_err;
			error = exfat_fat_set(pmp, last_cn, EXFAT_FAT_EOF);
			if (error != 0)
				goto fat_err;
			if (EXFAT_CLUSTER_VALID(pmp, next_cn))
				exfat_free_cluster_chain(pmp, next_cn, false,
				    0);
		}

		/* Invalidate flowcache and update LASTFC hint. */
		for (i = 0; i < EXFAT_FC_SIZE; i++) {
			np->node_fc[i].fc_frcn = EXFAT_FCE_EMPTY;
			np->node_fc[i].fc_fsrcn = EXFAT_FCE_EMPTY;
		}
		if (new_clusters > 0) {
			np->node_fc[EXFAT_FC_LASTFC].fc_frcn = new_clusters - 1;
			np->node_fc[EXFAT_FC_LASTFC].fc_fsrcn = last_cn;
		}
	}

	/*
	 * Phase 4: Commit new file size and valid data length.
	 *
	 * Update node_size and node_valid_size (Spec §7.6.5 & §7.6.7),
	 * notify the VM pager, and mark the node dirty. For directories,
	 * clamp node_valid_size to length so all remaining clusters are
	 * recognized as valid directory entry space, preserving §7.6.5.
	 */
	np->node_size = length;
	if ((np->node_attributes & EXFAT_ATTR_DIRECTORY) != 0 ||
	    np->node_valid_size > length)
		np->node_valid_size = length;
	if (NODETOV(np) != NULL)
		vnode_pager_setsize(NODETOV(np), length);
	np->node_flag |= EXFAT_NODE_DIRTY;
	return (0);

fat_err:
	/*
	 * Phase 2 already shrank the VM object size to length via vtruncbuf().
	 * Since FAT chain truncation failed before node_size was updated,
	 * restore the VM pager size to node_size so it stays consistent.
	 */
	if (NODETOV(np) != NULL)
		vnode_pager_setsize(NODETOV(np), np->node_size);
	return (error);
}
