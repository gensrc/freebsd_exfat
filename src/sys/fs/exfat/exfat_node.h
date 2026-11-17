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

#ifndef _FS_EXFAT_EXFAT_NODE_H_
#define _FS_EXFAT_EXFAT_NODE_H_

#include <sys/param.h>
#include <sys/buf.h>
#include <sys/fnv_hash.h>
#include <sys/vnode.h>

#include <fs/exfat/exfat_ondisk.h>

struct exfat_mount;

MALLOC_DECLARE(M_EXFATNODE);

/*
 * Pseudo-cluster and byte offset identifying the root directory node.
 * The root directory does not reside inside another directory, so it uses
 * a synthetic parent cluster and offset of (0, 0).
 */
#define EXFAT_ROOT_DIRCLUST		0x00000000U
#define EXFAT_ROOT_DIROFFSET		0x00000000U

#define EXFAT_IS_ROOT(clust, ofs) \
	((clust) == EXFAT_ROOT_DIRCLUST && (ofs) == EXFAT_ROOT_DIROFFSET)

/*
 * In-memory two-level cluster lookup cache for non-contiguous files.
 * Caches the most recent cluster mapping and the terminal cluster of the
 * file to accelerate sequential and appended I/O.
 */
#define EXFAT_FC_SIZE			2
#define EXFAT_FCE_EMPTY			0xFFFFFFFFU
#define EXFAT_FC_LASTMAP		0	/* Recent findcn:cn mapping */
#define EXFAT_FC_LASTFC			1	/* Last cluster in file */

struct exfat_cluster_cache {
	uint32_t	fc_frcn;	/* File-relative cluster number */
	uint32_t	fc_fsrcn;	/* Filesystem-relative cluster number */
};

/*
 * In-memory node representation for an exFAT file or directory
 * (equivalent to struct denode in msdosfs).
 *
 * Each node is uniquely identified by the directory cluster (node_dirclust)
 * and byte offset (node_diroffset) where its primary File Directory Entry
 * resides.  The 64-bit inode number (node_inode) is generated from these
 * two values via exfat_make_inode().
 *
 * Locking rules:
 * - node_vnode is locked via VFS vnode locks (VOP_LOCK / vget).
 * - Filesystem-wide metadata operations (allocation bitmap, FAT chains)
 *   require pmp->pm_lock.
 */
struct exfat_node {
	struct vnode			*node_vnode;	/* Back-pointer to vnode */
	struct vn_clusterw		node_clusterw;	/* Buffer write clustering */
	struct exfat_mount		*node_pmp;	/* Mount structure */

	/* Inode locator (directory cluster + entry byte offset) */
	uint32_t			node_dirclust;	/* Cluster holding directory entry set */
	uint32_t			node_diroffset;	/* Byte offset within directory cluster */
	uint64_t			node_inode;	/* Unique 64-bit file number (st_ino) */

	/* Parent directory locator */
	uint32_t			node_parent_dirclust;
	uint32_t			node_parent_diroffset;

	/* File metadata (from primary file & stream extension entries) */
	uint32_t			node_first_cluster; /* Starting cluster */
	uint64_t			node_size;	/* File size in bytes (DataLength) */
	uint64_t			node_valid_size;/* Initialized size (ValidDataLength) */
	uint16_t			node_attributes;/* EXFAT_ATTR_* */
	uint8_t				node_stream_flags;/* EXFAT_FLAG_* (NoFatChain, etc.) */
	uint8_t				node_secondary_count;

	/* Timestamps (packed MS-DOS format + sub-second/timezone) */
	uint32_t			node_ctime;	/* Creation timestamp */
	uint32_t			node_mtime;	/* Modification timestamp */
	uint32_t			node_atime;	/* Access timestamp */
	uint8_t				node_c_10ms;	/* Create 10ms increment */
	uint8_t				node_m_10ms;	/* Modify 10ms increment */
	uint8_t				node_c_tz;	/* Create timezone offset */
	uint8_t				node_m_tz;	/* Modify timezone offset */
	uint8_t				node_a_tz;	/* Access timezone offset */

	/* Runtime status flags */
	uint32_t			node_flag;	/* EXFAT_NODE_* runtime flags */

	/* Cluster cache */
	struct exfat_cluster_cache	node_fc[EXFAT_FC_SIZE];

	/* Directory free-slot allocation hint */
	uint32_t			node_dir_hint_clust;
	uint32_t			node_dir_hint_offset;
};

/*
 * In-memory node runtime flags (node_flag)
 */
#define EXFAT_NODE_MTIME	0x0001	/* Modification time update */
#define EXFAT_NODE_ATIME	0x0002	/* Access time update */
#define EXFAT_NODE_DIRTY	0x0004	/* Node metadata dirty */
#define EXFAT_NODE_UNLINKED	0x0008	/* Node unlinked, deferred free */

/*
 * Overlay for NFS file handle (struct fid)
 */
struct exfat_fid {
	uint16_t			fid_len;	/* Length of structure */
	uint16_t			fid_pad;	/* Alignment padding */
	uint32_t			fid_dirclust;	/* Cluster holding directory entry */
	uint32_t			fid_dirofs;	/* Offset within cluster */
};

_Static_assert(sizeof(struct exfat_fid) <= sizeof(struct fid),
    "struct exfat_fid cannot be larger than struct fid");

/*
 * Conversion macros
 */
#define VTONODE(vp)			((struct exfat_node *)((vp)->v_data))
#define VTONODE_SMR(vp)			\
	((struct exfat_node *)vn_load_v_data_smr(vp))
#define NODETOV(np)			((np)->node_vnode)

#ifdef _KERNEL

/*
 * Hash a 64-bit synthetic exFAT inode number into a 32-bit vfs_hash key.
 *
 * exFAT synthesizes inode numbers as ((dirclust << 32) | diroffset).
 * Because FreeBSD's vfs_hash subsystem accepts a 32-bit u_int hash, passing
 * the raw 64-bit inode directly discards the upper 32 bits (dirclust), causing
 * all files at the same directory offset across all directories to collide into
 * the same bucket.  Use FNV-1 32-bit hash over the full 64-bit inode to evenly
 * distribute entries across the vfs_hash table.
 */
static inline u_int
exfat_vnode_hash(uint64_t inode)
{
	return (fnv_32_buf(&inode, sizeof(inode), FNV1_32_INIT));
}

/*
 * Node management, sizing, and timestamp service routines
 */
int	exfat_vncmpf(struct vnode *vp, void *arg);
uint64_t exfat_make_inode(uint32_t dirclust, uint32_t diroffset);
int	exfat_node_get(struct exfat_mount *pmp, uint32_t dirclust,
	    uint32_t diroffset, int lkflags, struct exfat_node **nodepp);
void	exfat_node_free(struct exfat_node *np);
int	exfat_node_sync(struct exfat_node *np);
int	exfat_extend_file(struct exfat_node *np, uint64_t target_size);
int	exfat_truncate(struct exfat_node *np, uint64_t length);
void	exfat_times(struct exfat_node *np);

#endif /* _KERNEL */

#endif /* _FS_EXFAT_EXFAT_NODE_H_ */
