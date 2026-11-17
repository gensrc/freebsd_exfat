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
#include <sys/clock.h>
#include <sys/conf.h>
#include <sys/dirent.h>
#include <sys/endian.h>
#include <sys/extattr.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/limits.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/priv.h>
#include <sys/rwlock.h>
#include <sys/smr.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/unistd.h>
#include <sys/vmmeter.h>
#include <sys/vnode.h>
#include <security/audit/audit.h>
#include <security/mac/mac_framework.h>

#include <geom/geom.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vnode_pager.h>

#include <fs/exfat/exfat_fat.h>
#include <fs/exfat/exfat_ioctl.h>
#include <fs/exfat/exfat_lookup.h>
#include <fs/exfat/exfat_node.h>
#include <fs/exfat/exfat_ondisk.h>
#include <fs/exfat/exfat_subr.h>
#include <fs/exfat/exfat_unicode.h>
#include <fs/exfat/exfat_vfsops.h>
#include <fs/exfat/exfat_vnops.h>

VFS_SMR_DECLARE;

static int exfat_bmap_cluster(struct exfat_node *, uint32_t, uint32_t *);

static int
exfat_open(struct vop_open_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);

	if (np == NULL)
		return (EINVAL);

	vnode_create_vobject(vp, np->node_size, ap->a_td);
	return (0);
}

static int
exfat_close(struct vop_close_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);

	if (np == NULL)
		return (0);

	VI_LOCK(vp);
	if (vp->v_usecount > 1)
		exfat_times(np);
	VI_UNLOCK(vp);
	return (0);
}

static int
exfat_access(struct vop_access_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	struct exfat_mount *pmp;
	accmode_t accmode = ap->a_accmode;
	mode_t mode;

	if (np == NULL)
		return (EINVAL);

	pmp = np->node_pmp;

	if ((accmode & VWRITE) && (vp->v_mount->mnt_flag & MNT_RDONLY))
		return (EROFS);

	mode = S_IRWXU | S_IRWXG | S_IRWXO;
	if (np->node_attributes & EXFAT_ATTR_READ_ONLY)
		mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
	mode &= (vp->v_type == VDIR ? pmp->pm_dirmask : pmp->pm_mask);

	return (vaccess(vp->v_type, mode, pmp->pm_uid, pmp->pm_gid,
	    accmode, ap->a_cred));
}

/*
 * Lockless directory execution permission check for fast-path lookup
 * (cache_fplookup).
 *
 * Called within an SMR read section (vfs_smr_enter).  The directory vnode is
 * unlocked and unreferenced.
 *
 * In exFAT, file and directory permissions are not stored on disk; they are
 * synthesized entirely from static mount parameters (pm_dirmask, pm_uid,
 * pm_gid).  Read-only attributes (EXFAT_ATTR_READ_ONLY) only restrict write
 * access, never execute access.  If pm_dirmask grants execute permission to all
 * (e.g. 0755 or 0777), access is granted immediately without cred evaluation.
 *
 * Returns 0 if access is permitted, EACCES if denied, or EAGAIN if the check
 * cannot be safely completed locklessly.
 */
static int
exfat_fplookup_vexec(struct vop_fplookup_vexec_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np;
	struct exfat_mount *pmp;
	mode_t all_x, mode;

	np = VTONODE_SMR(vp);
	if (__predict_false(np == NULL))
		return (EAGAIN);

	pmp = VFSTOEXFAT(vp->v_mount);
	all_x = S_IXUSR | S_IXGRP | S_IXOTH;
	mode = S_IRWXU | S_IRWXG | S_IRWXO;
	mode &= (vp->v_type == VDIR ? pmp->pm_dirmask : pmp->pm_mask);
	if (__predict_true((mode & all_x) == all_x))
		return (0);

	return (vaccess_vexec_smr(mode, pmp->pm_uid, pmp->pm_gid,
	    ap->a_cred));
}

/*
 * Convert exFAT file attributes to BSD file flags.
 */
static inline u_long
exfat_attributes_to_fflags(uint16_t attrs)
{
	u_long flags;

	flags = 0;
	if ((attrs & EXFAT_ATTR_ARCHIVE) != 0)
		flags |= UF_ARCHIVE;
	if ((attrs & EXFAT_ATTR_HIDDEN) != 0)
		flags |= UF_HIDDEN;
	if ((attrs & EXFAT_ATTR_READ_ONLY) != 0)
		flags |= UF_READONLY;
	if ((attrs & EXFAT_ATTR_SYSTEM) != 0)
		flags |= UF_SYSTEM;
	return (flags);
}

static int
exfat_getattr(struct vop_getattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	struct exfat_mount *pmp;
	struct vattr *vap = ap->a_vap;
	mode_t mode;

	if (np == NULL)
		return (EINVAL);

	pmp = np->node_pmp;

	vap->va_fsid = pmp->pm_dev != NULL ? dev2udev(pmp->pm_dev) : 0;
	vap->va_fileid = np->node_inode;
	mode = S_IRWXU | S_IRWXG | S_IRWXO;
	if (np->node_attributes & EXFAT_ATTR_READ_ONLY)
		mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
	vap->va_mode = mode &
	    (vp->v_type == VDIR ? pmp->pm_dirmask : pmp->pm_mask);
	vap->va_nlink = ((np->node_flag & EXFAT_NODE_UNLINKED) != 0) ? 0 : 1;
	vap->va_uid = pmp->pm_uid;
	vap->va_gid = pmp->pm_gid;
	vap->va_rdev = NODEV;
	vap->va_size = np->node_size;
	if (UINT64_MAX - np->node_size < pmp->pm_cluster_mask)
		vap->va_bytes = np->node_size & ~(uint64_t)pmp->pm_cluster_mask;
	else
		vap->va_bytes = roundup2(np->node_size, pmp->pm_cluster_size);
	vap->va_blocksize = pmp->pm_cluster_size;
	vap->va_type = vp->v_type;
	vap->va_flags = exfat_attributes_to_fflags(np->node_attributes);
	vap->va_gen = 0;
	vap->va_filerev = 0;

	VI_LOCK(vp);
	exfat_times(np);
	VI_UNLOCK(vp);

	if (np->node_mtime != 0)
		exfat_fattime2timespec(np->node_mtime, np->node_m_10ms,
		    np->node_m_tz, &vap->va_mtime);
	else
		vfs_timestamp(&vap->va_mtime);
	if (np->node_atime != 0)
		exfat_fattime2timespec(np->node_atime, 0,
		    np->node_a_tz, &vap->va_atime);
	else
		vap->va_atime = vap->va_mtime;
	if (np->node_ctime != 0)
		exfat_fattime2timespec(np->node_ctime, np->node_c_10ms,
		    np->node_c_tz, &vap->va_ctime);
	else
		vap->va_ctime = vap->va_mtime;
	vap->va_birthtime = vap->va_ctime;

	return (0);
}

static int
exfat_stat(struct vop_stat_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	struct exfat_mount *pmp;
	struct stat *sb = ap->a_sb;
	mode_t mode;
	int error;

	if (np == NULL)
		return (EINVAL);

	pmp = np->node_pmp;

	error = vop_stat_helper_pre(ap);
	if (__predict_false(error))
		return (error);

	sb->st_dev = pmp->pm_dev != NULL ? dev2udev(pmp->pm_dev) : 0;
	sb->st_ino = np->node_inode;
	mode = S_IRWXU | S_IRWXG | S_IRWXO;
	if (np->node_attributes & EXFAT_ATTR_READ_ONLY)
		mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
	mode &= (vp->v_type == VDIR ? pmp->pm_dirmask : pmp->pm_mask);
	sb->st_mode = mode | VTTOIF(vp->v_type);
	sb->st_nlink = ((np->node_flag & EXFAT_NODE_UNLINKED) != 0) ? 0 : 1;
	sb->st_uid = pmp->pm_uid;
	sb->st_gid = pmp->pm_gid;
	sb->st_rdev = NODEV;
	if (np->node_size > OFF_MAX)
		return (vop_stat_helper_post(ap, EOVERFLOW));
	sb->st_size = np->node_size;
	sb->st_blksize = max(PAGE_SIZE, pmp->pm_cluster_size);
	sb->st_blocks = roundup2(np->node_size, pmp->pm_cluster_size) /
	    S_BLKSIZE;
	sb->st_flags = exfat_attributes_to_fflags(np->node_attributes);
	sb->st_gen = 0;

	VI_LOCK(vp);
	exfat_times(np);
	VI_UNLOCK(vp);

	if (np->node_mtime != 0)
		exfat_fattime2timespec(np->node_mtime, np->node_m_10ms,
		    np->node_m_tz, &sb->st_mtim);
	else
		vfs_timestamp(&sb->st_mtim);
	if (np->node_atime != 0)
		exfat_fattime2timespec(np->node_atime, 0,
		    np->node_a_tz, &sb->st_atim);
	else
		sb->st_atim = sb->st_mtim;
	if (np->node_ctime != 0)
		exfat_fattime2timespec(np->node_ctime, np->node_c_10ms,
		    np->node_c_tz, &sb->st_ctim);
	else
		sb->st_ctim = sb->st_mtim;
	sb->st_birthtim = sb->st_ctim;

	return (vop_stat_helper_post(ap, 0));
}

static int
exfat_setattr(struct vop_setattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	struct exfat_mount *pmp;
	struct vattr *vap = ap->a_vap;
	struct ucred *cred = ap->a_cred;
	struct thread *td = curthread;
	int error = 0;

	if (np == NULL)
		return (EINVAL);

	pmp = np->node_pmp;

	/*
	 * Check for unsettable attributes.
	 */
	if ((vap->va_type != VNON) || (vap->va_nlink != VNOVAL) ||
	    (vap->va_fsid != VNOVAL) || (vap->va_fileid != VNOVAL) ||
	    (vap->va_blocksize != VNOVAL) || (vap->va_rdev != VNOVAL) ||
	    (vap->va_bytes != VNOVAL) || (vap->va_gen != VNOVAL))
		return (EINVAL);

	/*
	 * Read-only filesystem cannot be modified.
	 */
	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	/*
	 * Disallow setting attributes on the root directory.
	 */
	if (vp->v_vflag & VV_ROOT)
		return (EINVAL);

	/*
	 * BSD File Flags (chflags).
	 */
	if (vap->va_flags != VNOVAL) {
		if (cred->cr_uid != pmp->pm_uid) {
			error = priv_check_cred(cred, PRIV_VFS_ADMIN);
			if (error != 0)
				return (error);
		}
		if ((vap->va_flags & ~(UF_ARCHIVE | UF_HIDDEN |
		    UF_READONLY | UF_SYSTEM)) != 0)
			return (EOPNOTSUPP);

		if (vap->va_flags & UF_ARCHIVE)
			np->node_attributes |= EXFAT_ATTR_ARCHIVE;
		else
			np->node_attributes &= ~EXFAT_ATTR_ARCHIVE;
		if (vap->va_flags & UF_HIDDEN)
			np->node_attributes |= EXFAT_ATTR_HIDDEN;
		else
			np->node_attributes &= ~EXFAT_ATTR_HIDDEN;
		if (vap->va_flags & UF_READONLY)
			np->node_attributes |= EXFAT_ATTR_READ_ONLY;
		else
			np->node_attributes &= ~EXFAT_ATTR_READ_ONLY;
		if (vap->va_flags & UF_SYSTEM)
			np->node_attributes |= EXFAT_ATTR_SYSTEM;
		else
			np->node_attributes &= ~EXFAT_ATTR_SYSTEM;
		np->node_flag |= EXFAT_NODE_DIRTY;
	}

	/*
	 * Ownership (UID / GID).
	 * exFAT does not store POSIX ownership on disk.
	 * Disallow changing ownership to any UID/GID other than the mount
	 * owner.
	 */
	if (vap->va_uid != (uid_t)VNOVAL || vap->va_gid != (gid_t)VNOVAL) {
		uid_t uid = vap->va_uid;
		gid_t gid = vap->va_gid;

		if (uid == (uid_t)VNOVAL)
			uid = pmp->pm_uid;
		if (gid == (gid_t)VNOVAL)
			gid = pmp->pm_gid;

		if (cred->cr_uid != pmp->pm_uid || uid != pmp->pm_uid ||
		    (gid != pmp->pm_gid && !groupmember(gid, cred))) {
			error = priv_check_cred(cred, PRIV_VFS_CHOWN);
			if (error != 0)
				return (error);
		}
		if (uid != pmp->pm_uid || gid != pmp->pm_gid)
			return (EINVAL);
	}

	/*
	 * Permissions (chmod).
	 * Only the write bit controls the EXFAT_ATTR_READ_ONLY attribute.
	 * Setting write bit on a directory does not affect DOS attributes
	 * (matches msdosfs).
	 */
	if (vap->va_mode != (mode_t)VNOVAL) {
		if (cred->cr_uid != pmp->pm_uid) {
			error = priv_check_cred(cred, PRIV_VFS_ADMIN);
			if (error != 0)
				return (error);
		}
		if (vp->v_type != VDIR) {
			if ((vap->va_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0)
				np->node_attributes |= EXFAT_ATTR_READ_ONLY;
			else
				np->node_attributes &= ~EXFAT_ATTR_READ_ONLY;
			np->node_flag |= EXFAT_NODE_DIRTY;
		}
	}

	/*
	 * File size / Truncation.
	 */
	if (vap->va_size != (u_quad_t)VNOVAL) {
		switch (vp->v_type) {
		case VDIR:
			return (EISDIR);
		case VREG:
			break;
		default:
			return (EINVAL);
		}
		error = vn_rlimit_trunc(vap->va_size, td);
		if (error != 0)
			return (error);
		error = exfat_truncate(np, vap->va_size);
		if (error != 0)
			return (error);
		/*
		 * Truncation modifies file content; mark node for timestamp
		 * update (mtime/atime) per exFAT Spec §7.4.6 & §7.4.7.
		 */
		np->node_flag |= EXFAT_NODE_MTIME;
	}

	/*
	 * Timestamps (Access / Modification / Creation birthtime).
	 *
	 * Handled after truncation so that size changes occur first.
	 * Flush any pending timestamp updates (such as EXFAT_NODE_MTIME from
	 * truncation or prior writes) before setting explicit timestamps;
	 * otherwise, a pending EXFAT_NODE_MTIME would overwrite an explicit
	 * va_atime when exfat_node_sync() invokes exfat_times().
	 */
	if (vap->va_mtime.tv_sec != VNOVAL || vap->va_atime.tv_sec != VNOVAL ||
	    vap->va_birthtime.tv_sec != VNOVAL) {
		error = vn_utimes_perm(vp, vap, cred, td);
		if (error != 0)
			return (error);

		exfat_times(np);

		if (vap->va_mtime.tv_sec != VNOVAL ||
		    vap->va_atime.tv_sec != VNOVAL) {
			uint16_t date, time;
			uint8_t hun;
			uint8_t tz = exfat_tz_offset();

			if (vap->va_mtime.tv_sec != VNOVAL) {
				timespec2fattime(&vap->va_mtime, 0, &date,
				    &time, &hun);
				np->node_mtime = ((uint32_t)date << 16) | time;
				np->node_m_10ms = hun;
				np->node_m_tz = tz;
			}
			if (vap->va_atime.tv_sec != VNOVAL) {
				timespec2fattime(&vap->va_atime, 0, &date,
				    &time, &hun);
				np->node_atime = ((uint32_t)date << 16) | time;
				np->node_a_tz = tz;
			}
			np->node_flag |= EXFAT_NODE_DIRTY;
		}

		if (vap->va_birthtime.tv_sec != VNOVAL) {
			uint16_t date, time;
			uint8_t hun;

			timespec2fattime(&vap->va_birthtime, 0, &date, &time,
			    &hun);
			np->node_ctime = ((uint32_t)date << 16) | time;
			np->node_c_10ms = hun;
			np->node_c_tz = exfat_tz_offset();
			np->node_flag |= EXFAT_NODE_DIRTY;
		}
	}

	if (np->node_flag & (EXFAT_NODE_DIRTY | EXFAT_NODE_MTIME))
		return (exfat_node_sync(np));

	return (0);
}

/*
 * Transfer count bytes of zeroed data to a uio scatter-gather buffer.
 *
 * Copies zeros from zero_region using vn_io_fault_uiomove() in PAGE_SIZE
 * chunks.  Used by exfat_read() when reading past ValidDataLength or reading
 * uninitialized holes in files.
 *
 * Returns 0 on success, or an error code from vn_io_fault_uiomove().
 */
static int
exfat_zeromove(size_t count, struct uio *uio)
{
	int chunk, error = 0;

	while (count > 0 && error == 0) {
		chunk = count > PAGE_SIZE ? PAGE_SIZE : (int)count;
		error = vn_io_fault_uiomove(__DECONST(void *, zero_region),
		    chunk, uio);
		count -= chunk;
	}
	return (error);
}

static int
exfat_read(struct vop_read_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct exfat_node *np = VTONODE(vp);
	struct exfat_mount *pmp = np->node_pmp;
	struct buf *bp;
	uint64_t filesize, valid_size;
	daddr_t lbn, rablock;
	int blsize, error = 0, seqcount;
	size_t n, on, to_read;
	ssize_t orig_resid;

	if (vp->v_type != VREG)
		return (EISDIR);

	if (uio->uio_resid == 0)
		return (0);

	if (uio->uio_offset < 0)
		return (EINVAL);

	orig_resid = uio->uio_resid;
	filesize = np->node_size;
	/*
	 * Gracefully clamp valid_size to filesize per exFAT Spec §7.6.5
	 * (ValidDataLength <= DataLength). Guarantees that read operations
	 * returning media data or calculating EOF zero-fill boundaries never
	 * exceed the allocated file size, even if in-memory node_valid_size
	 * transiently diverged.
	 */
	valid_size = min(np->node_valid_size, filesize);
	seqcount = ap->a_ioflag >> IO_SEQSHIFT;
	blsize = pmp->pm_cluster_size;

	if ((ap->a_ioflag & IO_DIRECT) != 0 &&
	    vp->v_bufobj.bo_dirty.bv_cnt > 0) {
		error = vinvalbuf(vp, V_SAVE, 0, 0);
		if (error != 0)
			return (error);
	}

	while (uio->uio_resid > 0 && (uint64_t)uio->uio_offset < filesize) {
		lbn = uio->uio_offset / pmp->pm_cluster_size;
		on = uio->uio_offset & pmp->pm_cluster_mask;
		n = blsize - on;
		if (n > (size_t)uio->uio_resid)
			n = (size_t)uio->uio_resid;
		if ((uint64_t)uio->uio_offset + n > filesize)
			n = (size_t)(filesize - uio->uio_offset);

		if ((uint64_t)uio->uio_offset >= valid_size) {
			error = exfat_zeromove(n, uio);
			if (error != 0)
				break;
			continue;
		}

		rablock = lbn + 1;
		if ((ap->a_ioflag & IO_DIRECT) != 0 ||
		    (uint64_t)rablock * pmp->pm_cluster_size >= valid_size ||
		    (vp->v_mount->mnt_flag & MNT_NOCLUSTERR) != 0)
			error = bread(vp, lbn, blsize, NOCRED, &bp);
		else
			error = cluster_read(vp, valid_size, lbn, blsize,
			    NOCRED, on + uio->uio_resid, seqcount, 0, &bp);

		if (error != 0) {
			if (bp != NULL)
				brelse(bp);
			break;
		}

		to_read = n;
		if ((uint64_t)uio->uio_offset + to_read > valid_size)
			to_read = (size_t)(valid_size - uio->uio_offset);

		error = vn_io_fault_uiomove(bp->b_data + on, to_read, uio);
		if ((ap->a_ioflag & IO_DIRECT) != 0)
			bp->b_flags |= B_DIRECT | B_RELBUF;
		brelse(bp);

		if (error == 0 && to_read < n)
			error = exfat_zeromove(n - to_read, uio);

		if (error != 0)
			break;
	}

	if (uio->uio_resid < orig_resid &&
	    (vp->v_mount->mnt_flag & (MNT_NOATIME | MNT_RDONLY)) == 0)
		np->node_flag |= EXFAT_NODE_ATIME;

	return (error);
}

/*
 * Zero a range of unwritten bytes [from, to) in a file.
 *
 * Iterates through the cluster-sized buffer cache blocks spanning [from, to).
 * If a block already exists in cache or a partial cluster must be preserved,
 * reads the block with bread() or allocates with getblk(), zeroes the byte
 * range, and marks the buffer dirty with bdwrite() (or writes it
 * synchronously with bwrite() when IO_SYNC is set in ioflag).
 *
 * Returns 0 on success, or an error from bread(), block resolution, or
 * synchronous writeback.
 */
static int
exfat_zero_range(struct exfat_node *np, uint64_t from, uint64_t to, int ioflag)
{
	struct exfat_mount *pmp = np->node_pmp;
	struct vnode *vp = NODETOV(np);
	struct buf *bp;
	uint64_t off;
	int error = 0;

	if (from >= to)
		return (0);
	/*
	 * Per exFAT Spec §7.6.5, media data between ValidDataLength and
	 * DataLength is undefined and must return zeroes for reads.
	 * Gracefully clamp 'to' to node_size to avoid zeroing past allocated
	 * clusters, and clamp 'from' to node_valid_size to avoid redundant
	 * zeroing over ranges that have already been initialized with data.
	 */
	if (to > np->node_size)
		to = np->node_size;
	if (from < np->node_valid_size)
		from = np->node_valid_size;
	if (from >= to)
		return (0);

	for (off = from; off < to; ) {
		daddr_t lbn = off / pmp->pm_cluster_size;
		size_t on = off & pmp->pm_cluster_mask;
		size_t n = pmp->pm_cluster_size - on;
		if (n > (size_t)(to - off))
			n = (size_t)(to - off);

		if (n == pmp->pm_cluster_size) {
			bp = getblk(vp, lbn, pmp->pm_cluster_size, 0, 0, 0);
			vfs_bio_clrbuf(bp);
		} else {
			error = bread(vp, lbn, pmp->pm_cluster_size, NOCRED,
			    &bp);
			if (error != 0) {
				if (bp != NULL)
					brelse(bp);
				break;
			}
			/*
			 * Only zero the requested [on, on + n) range here.
			 * Any newly-read pages in the uninitialized tail
			 * [on + n, cluster_size) were already zeroed by
			 * exfat_read_iodone() during bread(), while any pages
			 * in that tail that were already valid in vp->v_object
			 * (such as dirty mmap pages being paged out via
			 * UIO_NOCOPY starting at to) were preserved via
			 * bogus_page replacement and must not be clobbered.
			 */
			memset(bp->b_data + on, 0, n);
		}

		/*
		 * Translate logical cluster to physical disk block now
		 * while holding the vnode lock to avoid buffer cache
		 * recursion and lock inversion during asynchronous writeback.
		 */
		error = exfat_buf_resolve_blkno(np, bp);
		if (error != 0) {
			if ((bp->b_flags & B_DELWRI) == 0)
				bp->b_flags |= B_INVAL | B_RELBUF |
				    B_NOCACHE;
			brelse(bp);
			break;
		}

		if (ioflag & IO_SYNC) {
			error = bwrite(bp);
			if (error != 0) {
				np->node_valid_size = off;
				break;
			}
		} else
			bdwrite(bp);
		off += n;
		np->node_valid_size = off;
		np->node_flag |= EXFAT_NODE_MTIME | EXFAT_NODE_DIRTY;
	}
	return (error);
}

static int
exfat_write(struct vop_write_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct exfat_node *np = VTONODE(vp);
	struct exfat_mount *pmp = np->node_pmp;
	struct buf *bp;
	uint64_t osize, target_size;
	ssize_t r, resid;
	int error = 0, ioflag = ap->a_ioflag, seqcount;

	/*
	 * Phase 1: Pre-flight permission, append, and rlimit validation.
	 */
	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	if (vp->v_type != VREG)
		return (EISDIR);

	if (ioflag & IO_APPEND) {
		if (np->node_size > OFF_MAX)
			return (EFBIG);
		uio->uio_offset = np->node_size;
	}

	if (uio->uio_resid == 0)
		return (0);

	if (uio->uio_offset < 0)
		return (EINVAL);

	error = vn_rlimit_fsizex(vp, uio, OFF_MAX, &r, uio->uio_td);
	if (error != 0) {
		vn_rlimit_fsizex_res(uio, r);
		return (error);
	}

	if ((ioflag & IO_DIRECT) != 0 && vp->v_bufobj.bo_dirty.bv_cnt > 0) {
		error = vinvalbuf(vp, V_SAVE, 0, 0);
		if (error != 0)
			goto out;
	}

	/*
	 * Phase 2: Space allocation and sparse hole zeroing.
	 *
	 * Preallocate clusters via exfat_extend_file() if target write offset
	 * extends past current node_size. If writing beyond node_valid_size,
	 * explicitly zero the uninitialized hole via exfat_zero_range() to
	 * prevent exposing stale unwritten cluster contents (Spec Section
	 * 7.6.5).
	 */
	osize = np->node_size;
	resid = uio->uio_resid;
	if ((uint64_t)uio->uio_offset > UINT64_MAX - (uint64_t)uio->uio_resid) {
		error = EFBIG;
		goto out;
	}
	target_size = (uint64_t)uio->uio_offset + uio->uio_resid;
	if (target_size > osize) {
		error = exfat_extend_file(np, target_size);
		if (error != 0)
			goto out;
	}

	if ((uint64_t)uio->uio_offset > np->node_valid_size) {
		error = exfat_zero_range(np, np->node_valid_size,
		    uio->uio_offset, ioflag);
		if (error != 0) {
			if (target_size > osize)
				(void)exfat_truncate(np, osize);
			goto out;
		}
		np->node_valid_size = uio->uio_offset;
	}

	seqcount = ap->a_ioflag >> IO_SEQSHIFT;

	/*
	 * Phase 3: Cluster-by-cluster buffer I/O and data transfer.
	 *
	 * Iterate over target clusters. Allocate clean buffers via getblk()
	 * without reading from disk when writing full clusters or past
	 * node_valid_size; otherwise read existing contents via bread().
	 * Copy data via vn_io_fault_uiomove(), resolve physical block numbers,
	 * and dispatch dirty buffers.
	 */
	while (uio->uio_resid > 0) {
		daddr_t lbn = uio->uio_offset / pmp->pm_cluster_size;
		size_t on = uio->uio_offset & pmp->pm_cluster_mask;
		size_t n = pmp->pm_cluster_size - on;
		if (n > (size_t)uio->uio_resid)
			n = (size_t)uio->uio_resid;

		if (n == pmp->pm_cluster_size ||
		    (on == 0 &&
		    (uint64_t)uio->uio_offset >= np->node_valid_size)) {
			bp = getblk(vp, lbn, pmp->pm_cluster_size, 0, 0, 0);
			vfs_bio_clrbuf(bp);
		} else {
			error = bread(vp, lbn, pmp->pm_cluster_size, NOCRED,
			    &bp);
			if (error != 0) {
				if (bp != NULL)
					brelse(bp);
				break;
			}
		}

		/*
		 * Translate logical cluster to physical disk block now
		 * while holding the vnode lock.  Resolving b_blkno
		 * here avoids buffer cache recursion (calling bread()
		 * to read the FAT while already inside the bstrategy/
		 * bufdaemon flush path, which deadlocks when free
		 * buffers are exhausted) and prevents data races on
		 * the vnode cluster cache (node_fc).
		 */
		error = exfat_buf_resolve_blkno(np, bp);
		if (error != 0) {
			if ((bp->b_flags & B_DELWRI) == 0)
				bp->b_flags |= B_INVAL |
				    B_RELBUF | B_NOCACHE;
			brelse(bp);
			break;
		}

		error = vn_io_fault_uiomove(bp->b_data + on, n, uio);
		if (error != 0) {
			if ((bp->b_flags & B_DELWRI) == 0)
				bp->b_flags |= B_INVAL | B_RELBUF | B_NOCACHE;
			brelse(bp);
			break;
		}

		if ((uint64_t)uio->uio_offset > np->node_size)
			np->node_size = uio->uio_offset;
		if ((uint64_t)uio->uio_offset > np->node_valid_size)
			np->node_valid_size = uio->uio_offset;

		np->node_flag |= EXFAT_NODE_MTIME | EXFAT_NODE_DIRTY;

		if ((vp->v_mount->mnt_flag & MNT_NOCLUSTERW) == 0)
			bp->b_flags |= B_CLUSTEROK;

		if (ioflag & IO_SYNC) {
			error = bwrite(bp);
			if (error != 0)
				break;
		} else if (vm_page_count_severe() || buf_dirty_count_severe())
			bawrite(bp);
		else if (ioflag & IO_DIRECT) {
			bp->b_flags |= B_DIRECT;
			bawrite(bp);
		} else if (on + n == pmp->pm_cluster_size) {
			if ((vp->v_mount->mnt_flag & MNT_NOCLUSTERW) == 0)
				cluster_write(vp, &np->node_clusterw, bp,
				    np->node_size, seqcount, 0);
			else
				bawrite(bp);
		} else
			bdwrite(bp);
	}

	/*
	 * Phase 4: Error rollback and size reconciliation.
	 *
	 * On write failure, roll back allocated clusters via exfat_truncate()
	 * to prevent leaked preallocations, and reconcile resid counters.
	 */
	if (error != 0) {
		if ((ioflag & IO_UNIT) != 0) {
			(void)exfat_truncate(np, osize);
			uio->uio_offset -= resid - uio->uio_resid;
			uio->uio_resid = resid;
		} else {
			if (target_size > osize)
				(void)exfat_truncate(np,
				    max(osize, (uint64_t)uio->uio_offset));
			/*
			 * Per POSIX write(2), if write fails after partially
			 * transferring data, succeed with the byte count
			 * transferred so far.  Clear error so the syscall
			 * returns bytes written; subsequent write will fail.
			 */
			if (uio->uio_resid != resid)
				error = 0;
		}
	}
	if (error == 0 && (ioflag & IO_SYNC) != 0) {
		error = exfat_node_sync(np);
		if (error == 0 && pmp != NULL && pmp->pm_devvp != NULL) {
			vn_lock(pmp->pm_devvp, LK_EXCLUSIVE | LK_RETRY);
			error = VOP_FSYNC(pmp->pm_devvp, MNT_WAIT, curthread);
			VOP_UNLOCK(pmp->pm_devvp);
		}
	}

out:
	vn_rlimit_fsizex_res(uio, r);
	return (error);
}

static int
exfat_allocate(struct vop_allocate_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	off_t offset = *ap->a_offset;
	off_t len = *ap->a_len;
	uint64_t target_size;
	int error;

	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	if (vp->v_type != VREG)
		return (ENODEV);

	if (offset < 0 || len <= 0)
		return (EINVAL);

	if (offset > INT64_MAX - len)
		return (EFBIG);

	target_size = (uint64_t)(offset + len);

	if (target_size > np->node_size) {
		uint64_t osize = np->node_size;

		error = vn_rlimit_trunc(target_size, curthread);
		if (error != 0)
			return (error);
		error = exfat_extend_file(np, target_size);
		if (error != 0)
			return (error);
		np->node_flag |= EXFAT_NODE_MTIME;
		error = exfat_node_sync(np);
		if (error != 0) {
			(void)exfat_truncate(np, osize);
			return (error);
		}
	}

	*ap->a_offset = offset + len;
	*ap->a_len = 0;
	return (0);
}

static int
exfat_fsync(struct vop_fsync_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	struct exfat_mount *pmp;
	int allerror, error;

	allerror = vop_stdfsync(ap);

	if (np != NULL) {
		pmp = np->node_pmp;
		if ((np->node_flag & (EXFAT_NODE_MTIME | EXFAT_NODE_ATIME |
		    EXFAT_NODE_DIRTY)) != 0) {
			error = exfat_node_sync(np);
			if (allerror == 0)
				allerror = error;
		}
		if (ap->a_waitfor == MNT_WAIT && pmp != NULL &&
		    pmp->pm_devvp != NULL) {
			vn_lock(pmp->pm_devvp, LK_EXCLUSIVE | LK_RETRY);
			error = VOP_FSYNC(pmp->pm_devvp, MNT_WAIT, ap->a_td);
			VOP_UNLOCK(pmp->pm_devvp);
			if (allerror == 0)
				allerror = error;
		}
	}
	return (allerror);
}

static int
exfat_link(struct vop_link_args *ap)
{
	return (EOPNOTSUPP);
}

static int
exfat_symlink(struct vop_symlink_args *ap)
{
	return (EOPNOTSUPP);
}

static int
exfat_deleteextattr(struct vop_deleteextattr_args *ap)
{
	return (EOPNOTSUPP);
}

static int
exfat_getextattr(struct vop_getextattr_args *ap)
{
	return (EOPNOTSUPP);
}

static int
exfat_listextattr(struct vop_listextattr_args *ap)
{
	return (EOPNOTSUPP);
}

static int
exfat_setextattr(struct vop_setextattr_args *ap)
{
	return (EOPNOTSUPP);
}

/*
 * Map a file-relative cluster index to an on-disk filesystem cluster number.
 *
 * For contiguous streams (EXFAT_FLAG_NO_FAT_CHAIN), performs an O(1) addition
 * (first_cluster + frcn).  For FAT-chained streams, consults the per-node
 * two-entry cluster cache (node_fc[]) to find the closest preceding mapped
 * cluster, traverses the FAT chain to frcn, and updates the cache.
 *
 * Stores the on-disk cluster number in *fsrcnp.
 * Returns 0 on success, E2BIG if frcn is out of file bounds, ELOOP on cyclic
 * FAT loops, or an I/O error.
 */
static int
exfat_bmap_cluster(struct exfat_node *np, uint32_t frcn, uint32_t *fsrcnp)
{
	struct exfat_mount *pmp = np->node_pmp;
	uint64_t total_clusters_64;
	uint32_t cur_cn, cur_frcn, total_clusters, walked = 0;
	int error;

	if (np->node_size == 0 ||
	    !EXFAT_CLUSTER_VALID(pmp, np->node_first_cluster))
		return (E2BIG);

	if ((uint64_t)frcn * pmp->pm_cluster_size >= np->node_size)
		return (E2BIG);

	if (UINT64_MAX - np->node_size < pmp->pm_cluster_mask)
		return (EIO);
	total_clusters_64 = howmany(np->node_size, pmp->pm_cluster_size);
	if (total_clusters_64 > pmp->pm_cluster_count)
		return (EIO);
	total_clusters = (uint32_t)total_clusters_64;

	/* Contiguous stream (NoFatChain flag set) */
	if (np->node_stream_flags & EXFAT_FLAG_NO_FAT_CHAIN) {
		if (frcn >= pmp->pm_cluster_count ||
		    UINT32_MAX - np->node_first_cluster < frcn)
			return (EIO);
		cur_cn = np->node_first_cluster + frcn;
		if (!EXFAT_CLUSTER_VALID(pmp, cur_cn))
			return (EIO);
		*fsrcnp = cur_cn;
		return (0);
	}

	/* FAT-chained stream */
	cur_frcn = 0;
	cur_cn = np->node_first_cluster;

	/* Check cluster cache */
	if (np->node_fc[EXFAT_FC_LASTMAP].fc_frcn != EXFAT_FCE_EMPTY &&
	    np->node_fc[EXFAT_FC_LASTMAP].fc_frcn <= frcn) {
		if (EXFAT_CLUSTER_VALID(pmp,
		    np->node_fc[EXFAT_FC_LASTMAP].fc_fsrcn)) {
			cur_frcn = np->node_fc[EXFAT_FC_LASTMAP].fc_frcn;
			cur_cn = np->node_fc[EXFAT_FC_LASTMAP].fc_fsrcn;
		} else {
			np->node_fc[EXFAT_FC_LASTMAP].fc_frcn =
			    EXFAT_FCE_EMPTY;
			np->node_fc[EXFAT_FC_LASTMAP].fc_fsrcn =
			    EXFAT_FCE_EMPTY;
		}
	}
	if (np->node_fc[EXFAT_FC_LASTFC].fc_frcn != EXFAT_FCE_EMPTY &&
	    np->node_fc[EXFAT_FC_LASTFC].fc_frcn <= frcn &&
	    np->node_fc[EXFAT_FC_LASTFC].fc_frcn > cur_frcn) {
		if (EXFAT_CLUSTER_VALID(pmp,
		    np->node_fc[EXFAT_FC_LASTFC].fc_fsrcn)) {
			cur_frcn = np->node_fc[EXFAT_FC_LASTFC].fc_frcn;
			cur_cn = np->node_fc[EXFAT_FC_LASTFC].fc_fsrcn;
		} else {
			np->node_fc[EXFAT_FC_LASTFC].fc_frcn =
			    EXFAT_FCE_EMPTY;
			np->node_fc[EXFAT_FC_LASTFC].fc_fsrcn =
			    EXFAT_FCE_EMPTY;
		}
	}

	if (!EXFAT_CLUSTER_VALID(pmp, cur_cn))
		return (EIO);

	if (cur_frcn < frcn) {
		struct exfat_fat_cursor fc;

		exfat_fat_cursor_init(pmp, &fc);
		while (cur_frcn < frcn) {
			if (++walked > pmp->pm_cluster_count) {
				exfat_fat_cursor_put(&fc);
				return (ELOOP);
			}
			error = exfat_fat_cursor_get(&fc, cur_cn, &cur_cn);
			if (error != 0) {
				exfat_fat_cursor_put(&fc);
				return (error);
			}
			if (EXFAT_FAT_IS_EOF(cur_cn)) {
				exfat_fat_cursor_put(&fc);
				return (E2BIG);
			}
			if (!EXFAT_CLUSTER_VALID(pmp, cur_cn)) {
				exfat_fat_cursor_put(&fc);
				return (EIO);
			}
			cur_frcn++;
		}
		exfat_fat_cursor_put(&fc);
	}

	/* Update cluster cache */
	np->node_fc[EXFAT_FC_LASTMAP].fc_frcn = frcn;
	np->node_fc[EXFAT_FC_LASTMAP].fc_fsrcn = cur_cn;
	if (frcn == total_clusters - 1) {
		np->node_fc[EXFAT_FC_LASTFC].fc_frcn = frcn;
		np->node_fc[EXFAT_FC_LASTFC].fc_fsrcn = cur_cn;
	}

	*fsrcnp = cur_cn;
	return (0);
}

/*
 * Resolve logical cluster number (b_lblkno) to physical disk block (b_blkno).
 *
 * If b_blkno is already resolved (b_blkno != b_lblkno), this is a no-op.
 * Translates b_lblkno to a filesystem cluster via exfat_bmap_cluster(), then
 * converts the cluster number to a DEV_BSIZE disk block address using
 * exfat_cntodaddr() and stores the result in bp->b_blkno.
 *
 * Returns 0 on success, EFBIG if b_lblkno is out of range, or an error from
 * cluster mapping.
 */
int
exfat_buf_resolve_blkno(struct exfat_node *np, struct buf *bp)
{
	struct exfat_mount *pmp;
	uint32_t fsrcn;
	int error;

	if (bp->b_blkno != bp->b_lblkno)
		return (0);

	if (bp->b_lblkno < 0 || (uint64_t)bp->b_lblkno > UINT32_MAX)
		return (EFBIG);

	error = exfat_bmap_cluster(np, (uint32_t)bp->b_lblkno, &fsrcn);
	if (error != 0)
		return (error);

	pmp = np->node_pmp;
	bp->b_blkno = exfat_cntodaddr(pmp, fsrcn);
	return (0);
}

static int
exfat_bmap(struct vop_bmap_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	struct exfat_mount *pmp = np->node_pmp;
	struct mount *mp = vp->v_mount;
	uint64_t total_clusters_64;
	uint32_t cn, fsrcn, total_clusters;
	int error, maxio, maxrun, run;

	if (ap->a_bop != NULL)
		*ap->a_bop = pmp->pm_bo;
	if (ap->a_bnp == NULL)
		return (0);
	if (ap->a_runp != NULL)
		*ap->a_runp = 0;
	if (ap->a_runb != NULL)
		*ap->a_runb = 0;

	cn = (uint32_t)ap->a_bn;
	if (ap->a_bn < 0 || (daddr_t)cn != ap->a_bn)
		return (EFBIG);

	error = exfat_bmap_cluster(np, cn, &fsrcn);
	if (error != 0)
		return (error);

	*ap->a_bnp = exfat_cntodaddr(pmp, fsrcn);

	if (ap->a_runp == NULL && ap->a_runb == NULL)
		return (0);

	maxio = mp->mnt_iosize_max / pmp->pm_cluster_size;
	if (maxio < 1)
		maxio = 1;
	if (UINT64_MAX - np->node_size < pmp->pm_cluster_mask)
		return (EIO);
	total_clusters_64 = howmany(np->node_size, pmp->pm_cluster_size);
	if (total_clusters_64 > pmp->pm_cluster_count)
		return (EIO);
	total_clusters = (uint32_t)total_clusters_64;

	if (np->node_stream_flags & EXFAT_FLAG_NO_FAT_CHAIN) {
		if (ap->a_runp != NULL) {
			uint32_t heap_avail;

			run = (total_clusters > cn + 1) ?
			    (total_clusters - (cn + 1)) : 0;
			if (run > maxio - 1)
				run = maxio - 1;
			heap_avail = (pmp->pm_cluster_count >
			    (EXFAT_CNTOI(fsrcn) + 1)) ?
			    (pmp->pm_cluster_count -
			    (EXFAT_CNTOI(fsrcn) + 1)) : 0;
			if ((uint32_t)run > heap_avail)
				run = (int)heap_avail;
			*ap->a_runp = run;
		}
		if (ap->a_runb != NULL) {
			run = cn;
			if (run > maxio - 1)
				run = maxio - 1;
			*ap->a_runb = run;
		}
		return (0);
	}

	if (ap->a_runp != NULL) {
		maxrun = (total_clusters > cn + 1) ?
		    (total_clusters - (cn + 1)) : 0;
		if (maxrun > maxio - 1)
			maxrun = maxio - 1;
		exfat_fat_contig_forward(pmp, fsrcn, maxrun, &run);
		*ap->a_runp = run;
	}

	if (ap->a_runb != NULL) {
		maxrun = (cn < (uint32_t)(maxio - 1)) ?
		    cn : (uint32_t)(maxio - 1);
		exfat_fat_contig_backward(pmp, fsrcn, maxrun, &run);
		*ap->a_runb = run;
	}

	return (0);
}

/*
 * I/O completion callback for read buffers straddling ValidDataLength.
 *
 * Zeroes the uninitialized tail of the buffer starting at valid_off (stored in
 * b_fsprivate1).  For B_VMIO buffers, zeroes physical pages via
 * pmap_zero_page_area() to avoid overwriting bogus_page substitutions.  For
 * non-VMIO or malloc buffers, zeroes the contiguous KVA buffer.  Restores
 * original b_iodone and invokes bufdone().
 */
static void
exfat_read_iodone(struct buf *bp)
{
	size_t valid_off;

	valid_off = (size_t)(uintptr_t)bp->b_fsprivate1;
	bp->b_fsprivate1 = NULL;
	bp->b_iodone = bp->b_fsprivate2;
	bp->b_fsprivate2 = NULL;

	if ((bp->b_ioflags & BIO_ERROR) == 0 &&
	    valid_off < (size_t)bp->b_bcount) {
		/*
		 * For B_VMIO buffers (excluding B_MALLOC), zero the physical
		 * pages individually via pmap_zero_page_area() to avoid
		 * clobbering bogus_page substitutions.  For non-VMIO or
		 * B_MALLOC buffers, no VM object pages are attached, and
		 * bp->b_data is a contiguous kernel virtual address.
		 */
		if ((bp->b_flags & (B_VMIO | B_MALLOC)) == B_VMIO) {
			size_t base = (bp->b_offset & PAGE_MASK) + valid_off;
			size_t end = (bp->b_offset & PAGE_MASK) +
			    (size_t)bp->b_bcount;

			while (base < end) {
				int pg_idx = base >> PAGE_SHIFT;
				size_t pg_off = base & PAGE_MASK;
				size_t pg_len = PAGE_SIZE - pg_off;

				if (pg_len > end - base)
					pg_len = end - base;
				if (pg_idx < bp->b_npages &&
				    bp->b_pages[pg_idx] != bogus_page)
					pmap_zero_page_area(
					    bp->b_pages[pg_idx], pg_off,
					    pg_len);
				base += pg_len;
			}
		} else
			/* Non-VMIO / B_MALLOC: zero contiguous KVA. */
			memset(bp->b_data + valid_off, 0,
			    (size_t)bp->b_bcount - valid_off);
	}
	bufdone(bp);
}

static int
exfat_strategy(struct vop_strategy_args *ap)
{
	struct buf *bp = ap->a_bp;
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	struct exfat_mount *pmp = np->node_pmp;
	int error;

	if (vp->v_type == VREG && bp->b_lblkno >= 0) {
		uint64_t blk_off = (uint64_t)bp->b_lblkno *
		    pmp->pm_cluster_size;
		/*
		 * Clamp valid_size to node_size per Spec §7.6.5 so bio reads
		 * beyond file EOF are immediately zero-filled without disk I/O.
		 */
		uint64_t valid_size = min(np->node_valid_size, np->node_size);

		/*
		 * If reading at or beyond initialized data (node_valid_size),
		 * zero the buffer and complete the I/O immediately without
		 * issuing disk I/O.  Note that bp->b_blkno is left unresolved
		 * (bp->b_blkno == bp->b_lblkno) when returning 0; if this
		 * buffer is later modified in cache, synchronous resolution
		 * in write paths (e.g. exfat_write) will translate it before
		 * writeback.
		 */
		if (bp->b_iocmd == BIO_READ && blk_off >= valid_size) {
			vfs_bio_clrbuf(bp);
			bufdone(bp);
			return (0);
		}
		if (bp->b_iocmd == BIO_WRITE &&
		    blk_off <= np->node_valid_size) {
			uint64_t end_off = blk_off + bp->b_bcount;

			/*
			 * Gracefully clamp end_off to node_size so writeback
			 * cannot advance node_valid_size past allocated EOF.
			 */
			if (end_off > np->node_size)
				end_off = np->node_size;
			if (end_off > np->node_valid_size) {
				np->node_valid_size = end_off;
				np->node_flag |= EXFAT_NODE_MTIME |
				    EXFAT_NODE_DIRTY;
			}
		}
	}

	error = exfat_buf_resolve_blkno(np, bp);
	if (error != 0) {
		bp->b_error = error;
		bp->b_ioflags |= BIO_ERROR;
		bufdone(bp);
		return (0);
	}

	if (vp->v_type == VREG && bp->b_lblkno >= 0 &&
	    bp->b_iocmd == BIO_READ) {
		uint64_t blk_off = (uint64_t)bp->b_lblkno *
		    pmp->pm_cluster_size;
		/*
		 * Clamp valid_size to node_size (Spec §7.6.5) so zeroing
		 * of uninitialized tails never extends past file bounds.
		 */
		uint64_t valid_size = min(np->node_valid_size, np->node_size);

		/*
		 * When reading a cluster that straddles node_valid_size,
		 * zero the uninitialized tail [valid_size, end) in b_iodone
		 * before vfs_vmio_iodone() marks the pages valid and restores
		 * bogus_page entries.  This ensures all pages in the cluster
		 * (including vfs_bio_getpages() read-behind and read-ahead
		 * pages) have their uninitialized regions zeroed before
		 * becoming visible in vp->v_object, while preserving any
		 * pages that were already valid (and potentially dirtied via
		 * mmap) prior to the read.
		 */
		if (blk_off < valid_size &&
		    blk_off + bp->b_bcount > valid_size) {
			bp->b_fsprivate1 =
			    (void *)(uintptr_t)(valid_size - blk_off);
			bp->b_fsprivate2 = bp->b_iodone;
			bp->b_iodone = exfat_read_iodone;
		}
	}

	bp->b_iooffset = dbtob(bp->b_blkno);
	BO_STRATEGY(pmp->pm_bo, bp);
	return (0);
}

/*
 * VFS vfs_bio_getpages callback to compute logical cluster block number (lbn)
 * from file byte offset.
 *
 * Returns off divided by pm_cluster_size.
 */
static daddr_t
exfat_gbp_getblkno(struct vnode *vp, vm_ooffset_t off)
{
	struct exfat_node *np = VTONODE(vp);

	return (off / np->node_pmp->pm_cluster_size);
}

/*
 * VFS vfs_bio_getpages callback to return filesystem cluster block size.
 *
 * Stores pm_cluster_size in *sz and returns 0.
 */
static int
exfat_gbp_getblksz(struct vnode *vp, daddr_t lbn __unused, long *sz)
{
	struct exfat_node *np = VTONODE(vp);

	*sz = np->node_pmp->pm_cluster_size;
	return (0);
}

static int
exfat_getpages(struct vop_getpages_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);

	if (np == NULL)
		return (VM_PAGER_BAD);

	return (vfs_bio_getpages(vp, ap->a_m, ap->a_count, ap->a_rbehind,
	    ap->a_rahead, exfat_gbp_getblkno, exfat_gbp_getblksz));
}

static int
exfat_print(struct vop_print_args *ap)
{
	struct exfat_node *np = VTONODE(ap->a_vp);

	if (np == NULL)
		return (0);

	printf("\ttag VT_EXFAT, inode %ju, cluster %u, offset %u\n",
	    (uintmax_t)np->node_inode, np->node_dirclust, np->node_diroffset);
	return (0);
}

/*
 * Online Volume Label modification helper.
 *
 * Searches the root directory for an existing Volume Label entry (0x83) per
 * exFAT Spec §7.3.  If label is empty or NULL, deletes the existing volume
 * label entry.  Otherwise, validates label syntax with exfat_is_valid_label(),
 * converts to UTF-16, and updates or inserts the Volume Label entry.  Updates
 * pmp->pm_vollabel in memory.
 *
 * Returns 0 on success, EINVAL on invalid characters or length, or an I/O
 * error.
 */
static int
exfat_set_vollabel(struct vnode *vp, const char *label, struct ucred *cred)
{
	struct exfat_mount *pmp;
	struct vnode *root_vp;
	struct exfat_node *root_np;
	struct exfat_dir_cursor dc;
	const union exfat_dentry *dent;
	union exfat_dentry new_dent;
	uint16_t utf16_label[EXFAT_MAX_VOLUME_LABEL_CHARS];
	size_t nchars = 0, srclen;
	uint32_t entry_clust, entry_offset;
	uint32_t found_label_clust = 0, found_label_offset = 0;
	bool found_label = false, root_locked = false;
	int error;

	pmp = VFSTOEXFAT(vp->v_mount);
	if (pmp == NULL)
		return (EINVAL);

	if ((pmp->pm_mountp->mnt_flag & MNT_RDONLY) != 0 ||
	    (pmp->pm_flags & EXFAT_MNT_RONLY) != 0)
		return (EROFS);

	if (cred != NULL && pmp->pm_uid != cred->cr_uid) {
		error = priv_check_cred(cred, PRIV_VFS_ADMIN);
		if (error != 0)
			return (error);
	}

	srclen = strnlen(label, EXFAT_MAX_LABEL_LEN);
	if (srclen >= EXFAT_MAX_LABEL_LEN)
		return (EINVAL);

	if (srclen > 0) {
		error = exfat_utf8_to_utf16(label, srclen, utf16_label,
		    EXFAT_MAX_VOLUME_LABEL_CHARS, &nchars);
		if (error != 0)
			return (error);
		if (!exfat_is_valid_label(utf16_label, nchars))
			return (EINVAL);
	}

	if (VTONODE(vp) != NULL &&
	    EXFAT_IS_ROOT(VTONODE(vp)->node_dirclust,
	    VTONODE(vp)->node_diroffset) &&
	    VOP_ISLOCKED(vp) == LK_EXCLUSIVE) {
		root_vp = vp;
		vref(root_vp);
		root_locked = false;
	} else {
		error = VFS_ROOT(pmp->pm_mountp, LK_EXCLUSIVE, &root_vp);
		if (error != 0)
			return (error);
		root_locked = true;
	}

	root_np = VTONODE(root_vp);

	/* Scan root directory for an existing Volume Label entry */
	exfat_dir_cursor_init(pmp, root_np, &dc);
	while ((error = exfat_dir_cursor_get(&dc, &dent, &entry_clust,
	    &entry_offset)) == 0) {
		if (dent == NULL)
			break;
		if (dent->type == EXFAT_ENTRY_EOD)
			break;
		if (dent->type == EXFAT_ENTRY_VOLUME_LABEL) {
			found_label = true;
			found_label_clust = entry_clust;
			found_label_offset = entry_offset;
			break;
		}
		if (dent->type == EXFAT_ENTRY_FILE &&
		    dent->file.fe_secondary_count <=
		    EXFAT_MAX_SECONDARY_COUNT) {
			error = exfat_dir_cursor_skip(&dc,
			    dent->file.fe_secondary_count);
			if (error != 0)
				break;
		}
		error = exfat_dir_cursor_next(&dc);
		if (error != 0)
			break;
	}
	exfat_dir_cursor_put(&dc);

	if (error != 0 && error != ENOENT)
		goto out;

	if (nchars > 0) {
		memset(&new_dent, 0, sizeof(new_dent));
		new_dent.volume_label.vl_type = EXFAT_ENTRY_VOLUME_LABEL;
		new_dent.volume_label.vl_character_count = (uint8_t)nchars;
		for (size_t i = 0; i < nchars; i++)
			new_dent.volume_label.vl_volume_label[i] =
			    htole16(utf16_label[i]);

		if (found_label)
			error = exfat_dentry_write_set(pmp, root_np,
			    found_label_clust, found_label_offset,
			    &new_dent, 1);
		else {
			uint32_t slot_clust, slot_offset;

			error = exfat_dentry_find_free_slot(root_np, 1,
			    &slot_clust, &slot_offset);
			if (error == 0)
				error = exfat_dentry_write_set(pmp, root_np,
				    slot_clust, slot_offset, &new_dent, 1);
		}
	} else if (found_label)
		error = exfat_dentry_delete_set(pmp, root_np,
		    found_label_clust, found_label_offset, 1);
	else
		error = 0;

	if (error == 0)
		error = VOP_FSYNC(root_vp, MNT_WAIT, curthread);
	if (error == 0) {
		EXFAT_LOCK(pmp);
		strlcpy(pmp->pm_vollabel, label, sizeof(pmp->pm_vollabel));
		EXFAT_UNLOCK(pmp);
	}

out:
	if (root_locked)
		vput(root_vp);
	else
		vrele(root_vp);
	return (error);
}

static int
exfat_ioctl(struct vop_ioctl_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np;
	struct exfat_mount *pmp;
	struct fiodgname_arg *fgn;
	const char *p;
	off_t *offp;
	uint64_t file_size, valid_size;
	char labelbuf[EXFAT_MAX_LABEL_LEN];
	int error, i;

	switch (ap->a_command) {
	case FIOSEEKDATA:
	case FIOSEEKHOLE:
		/*
		 * Exfat vnodes do not opt into shared locking (VN_LOCK_ASHARE);
		 * lock exclusively.
		 */
		error = vn_lock(vp, LK_EXCLUSIVE);
		if (error != 0)
			return (EBADF);
		if (vp->v_type != VREG) {
			VOP_UNLOCK(vp);
			return (ENOTTY);
		}
		np = VTONODE(vp);
		if (np == NULL) {
			VOP_UNLOCK(vp);
			return (EINVAL);
		}
		offp = (off_t *)ap->a_data;
		file_size = np->node_size;
		/*
		 * Gracefully clamp valid_size to file_size (Spec §7.6.5) so
		 * FIOSEEKDATA and FIOSEEKHOLE bounds calculations cannot report
		 * a data or hole offset beyond the allocated file size.
		 */
		valid_size = min(np->node_valid_size, file_size);

		/*
		 * Unlike filesystems with per-block extent maps or hole trees,
		 * exFAT allocates all clusters up to node_size and represents
		 * sparse/unwritten ranges via ValidDataLength
		 * (node_valid_size). The range [0, valid_size) is valid data,
		 * and [valid_size, file_size) is an unwritten hole (read as
		 * zeroes). Hence, no cluster chain traversal is needed:
		 * offsets before valid_size are in data, and offsets at or
		 * beyond valid_size are in a hole.
		 */
		error = 0;
		if (*offp < 0 || (uint64_t)*offp >= file_size)
			error = ENXIO;
		else if (ap->a_command == FIOSEEKDATA &&
		    (uint64_t)*offp >= valid_size)
			error = ENXIO;
		else if (ap->a_command == FIOSEEKHOLE &&
		    (uint64_t)*offp < valid_size)
			*offp = (off_t)valid_size;
		VOP_UNLOCK(vp);
		return (error);
	case FIODGNAME:
#ifdef COMPAT_FREEBSD32
	case FIODGNAME_32:
#endif
		pmp = VFSTOEXFAT(vp->v_mount);
		if (pmp == NULL)
			return (EINVAL);
		p = NULL;
		if (pmp->pm_dev != NULL)
			p = devtoname(pmp->pm_dev);
		else if (pmp->pm_cp != NULL && pmp->pm_cp->provider != NULL)
			p = pmp->pm_cp->provider->name;
		if (p == NULL)
			return (ENXIO);

		fgn = (struct fiodgname_arg *)ap->a_data;
		i = strlen(p) + 1;
		if (i > fgn->len)
			return (EINVAL);
		return (copyout(p, fiodgname_buf_get_ptr(fgn, ap->a_command),
		    i));
	case FIODTYPE:
		*(int *)ap->a_data = D_DISK;
		return (0);
	case EXFATIOC_GETLABEL:
		pmp = VFSTOEXFAT(vp->v_mount);
		if (pmp == NULL)
			return (EINVAL);
		EXFAT_LOCK(pmp);
		strlcpy((char *)ap->a_data, pmp->pm_vollabel,
		    EXFAT_MAX_LABEL_LEN);
		EXFAT_UNLOCK(pmp);
		return (0);
	case EXFATIOC_SETLABEL:
		if (memchr(ap->a_data, '\0', EXFAT_MAX_LABEL_LEN) == NULL)
			return (EINVAL);
		strlcpy(labelbuf, (const char *)ap->a_data, sizeof(labelbuf));
		return (exfat_set_vollabel(vp, labelbuf, ap->a_cred));
	default:
		return (ENOTTY);
	}
}

static int
exfat_pathconf(struct vop_pathconf_args *ap)
{
	struct exfat_node *np = VTONODE(ap->a_vp);
	struct exfat_mount *pmp = np->node_pmp;

	switch (ap->a_name) {
	case _PC_FILESIZEBITS:
		*ap->a_retval = 64;
		return (0);
	case _PC_LINK_MAX:
		*ap->a_retval = 1;
		return (0);
	case _PC_NAME_MAX:
		*ap->a_retval = EXFAT_MAX_NAME_CHARS;
		return (0);
	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX;
		return (0);
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		return (0);
	case _PC_NO_TRUNC:
		*ap->a_retval = 1;
		return (0);
	case _PC_ALLOC_SIZE_MIN:
		*ap->a_retval = pmp->pm_cluster_size;
		return (0);
	case _PC_MIN_HOLE_SIZE:
		*ap->a_retval = pmp->pm_cluster_size;
		return (0);
	case _PC_REC_INCR_XFER_SIZE:
		*ap->a_retval = pmp->pm_cluster_size;
		return (0);
	case _PC_REC_MIN_XFER_SIZE:
		*ap->a_retval = pmp->pm_cluster_size;
		return (0);
	case _PC_REC_MAX_XFER_SIZE:
		*ap->a_retval = -1;
		return (0);
	case _PC_REC_XFER_ALIGN:
		*ap->a_retval = PAGE_SIZE;
		return (0);
	case _PC_HAS_HIDDENSYSTEM:
		*ap->a_retval = 1;
		return (0);
	case _PC_CASE_INSENSITIVE:
		*ap->a_retval = 1;
		return (0);
	case _PC_DEALLOC_PRESENT:
		*ap->a_retval = 1;
		return (0);
	case _PC_SYMLINK_MAX:
		return (EOPNOTSUPP);
	default:
		return (vop_stdpathconf(ap));
	}
}

#if __FreeBSD_version >= 1600019
static int
exfat_update_atime(struct vop_update_atime_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	struct mount *mp = vp->v_mount;

	if (np == NULL)
		return (EINVAL);

	if ((mp->mnt_flag & (MNT_NOATIME | MNT_RDONLY)) != 0)
		return (0);

	if (ap->a_ts != NULL) {
		uint16_t date, time;
		uint8_t hun;
		timespec2fattime(ap->a_ts, 0, &date, &time, &hun);
		np->node_atime = ((uint32_t)date << 16) | time;
		np->node_a_tz = exfat_tz_offset();
		np->node_flag &= ~EXFAT_NODE_ATIME;
		np->node_flag |= EXFAT_NODE_DIRTY;
	} else
		np->node_flag |= EXFAT_NODE_ATIME | EXFAT_NODE_DIRTY;
	return (0);
}
#else
static int
exfat_mmapped(struct vop_mmapped_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	struct mount *mp = vp->v_mount;

	if (np == NULL)
		return (EINVAL);

	if ((mp->mnt_flag & (MNT_NOATIME | MNT_RDONLY)) != 0)
		return (0);

	np->node_flag |= EXFAT_NODE_ATIME | EXFAT_NODE_DIRTY;
	return (0);
}
#endif

static int
exfat_vptofh(struct vop_vptofh_args *ap)
{
	struct exfat_node *np;
	struct exfat_fid *fid;

	np = VTONODE(ap->a_vp);
	if (np == NULL || (np->node_flag & EXFAT_NODE_UNLINKED) != 0)
		return (ESTALE);

	fid = (struct exfat_fid *)ap->a_fhp;
	fid->fid_len = sizeof(struct exfat_fid);
	fid->fid_pad = 0;
	fid->fid_dirclust = np->node_dirclust;
	fid->fid_dirofs = np->node_diroffset;
	return (0);
}

static int
exfat_mknod(struct vop_mknod_args *ap)
{
	return (EINVAL);
}

/*
 * Helper context for fetching parent directory (..) vnode.
 */
struct exfat_get_dotdot {
	struct exfat_mount	*pmp;
	uint32_t		dirclust;
	uint32_t		diroffset;
};

/*
 * VFS vn_vget_ino_gen callback for ".." parent directory lookups.
 *
 * Unpacks the parent directory cluster and offset from arg (struct
 * exfat_get_dotdot) and retrieves the locked parent vnode via
 * exfat_node_get().
 *
 * Stores the locked parent vnode in *rvp.
 * Returns 0 on success, or an error code from exfat_node_get().
 */
static int
exfat_node_get_dotdot(struct mount *mp __unused, void *arg, int lkflags,
    struct vnode **rvp)
{
	struct exfat_get_dotdot *dd = arg;
	struct exfat_node *np;
	int error;

	error = exfat_node_get(dd->pmp, dd->dirclust, dd->diroffset,
	    lkflags, &np);
	if (error != 0)
		return (error);

	*rvp = NODETOV(np);
	return (0);
}

static int
exfat_lookup(struct vop_cachedlookup_args *ap)
{
	struct vnode *vdp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct exfat_node *dp = VTONODE(vdp);
	struct exfat_mount *pmp = dp->node_pmp;
	struct exfat_node *np;
	struct exfat_dir_cursor dc;
	uint16_t target_utf16[EXFAT_MAX_NAME_CHARS];
	size_t target_nchars;
	uint16_t target_hash;
	int error;

	if (vpp != NULL)
		*vpp = NULL;

	if (vdp->v_type != VDIR)
		return (ENOTDIR);

	if ((dp->node_flag & EXFAT_NODE_UNLINKED) != 0)
		return (ENOENT);

	/* Check for "." */
	if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') {
		if ((cnp->cn_flags & ISLASTCN) != 0) {
			if (cnp->cn_nameiop == DELETE)
				return (EINVAL);
			if (cnp->cn_nameiop == RENAME)
				return (EISDIR);
		}
		vref(vdp);
		if (vpp != NULL)
			*vpp = vdp;
		return (0);
	}

	/* Check for ".." */
	if (cnp->cn_flags & ISDOTDOT) {
		struct exfat_get_dotdot dd;

		if ((cnp->cn_flags & ISLASTCN) != 0) {
			if (cnp->cn_nameiop == DELETE)
				return (ENOTEMPTY);
			if (cnp->cn_nameiop == RENAME)
				return (EINVAL);
		}

		if (vdp->v_vflag & VV_ROOT) {
			vref(vdp);
			if (vpp != NULL)
				*vpp = vdp;
			return (0);
		}

		dd.pmp = pmp;
		dd.dirclust = dp->node_parent_dirclust;
		dd.diroffset = dp->node_parent_diroffset;

		return (vn_vget_ino_gen(vdp, exfat_node_get_dotdot, &dd,
		    cnp->cn_lkflags, vpp));
	}

	/* Convert lookup target from UTF-8 to UTF-16 */
	error = exfat_utf8_to_utf16(cnp->cn_nameptr, cnp->cn_namelen,
	    target_utf16, EXFAT_MAX_NAME_CHARS, &target_nchars);
	if (error != 0) {
		if (error == ENAMETOOLONG)
			return (ENOENT);
		return (error);
	}

	/* Compute 16-bit hash of upcased target name */
	target_hash = exfat_name_hash(pmp, target_utf16, target_nchars);

	exfat_dir_cursor_init(pmp, dp, &dc);

	while (1) {
		const union exfat_dentry *dent;
		union exfat_dentry prim_dent;
		struct exfat_dentry_stream stream;
		uint16_t file_utf16[EXFAT_MAX_NAME_CHARS];
		size_t chars_read, num_name_entries;
		uint32_t prim_cluster, prim_offset;
		uint16_t cs, name_hash, set_checksum;
		uint8_t name_len, sec_idx, secondary_count;
		bool valid_set;

		error = exfat_dir_cursor_get(&dc, &dent, &prim_cluster,
		    &prim_offset);
		if (error != 0)
			break;

		if (dent->type == EXFAT_ENTRY_EOD)
			break;

		if ((dent->type & EXFAT_ENTRY_TYPE_IN_USE) == 0 ||
		    dent->type != EXFAT_ENTRY_FILE) {
			error = exfat_dir_cursor_next(&dc);
			if (error != 0)
				break;
			continue;
		}

		/* We have a primary file entry (0x85) */
		secondary_count = dent->file.fe_secondary_count;

		if (secondary_count < EXFAT_MIN_SECONDARY_COUNT ||
		    secondary_count > EXFAT_MAX_SECONDARY_COUNT) {
			error = exfat_dir_cursor_next(&dc);
			if (error != 0)
				break;
			continue;
		}
		prim_dent = *dent;
		set_checksum = le16toh(prim_dent.file.fe_set_checksum);

		/* Advance to Stream Extension entry (0xC0) */
		error = exfat_dir_cursor_next(&dc);
		if (error != 0)
			break;

		error = exfat_dir_cursor_get(&dc, &dent, NULL, NULL);
		if (error != 0)
			break;

		if (dent->type != EXFAT_ENTRY_STREAM) {
			error = exfat_dir_cursor_skip(&dc, secondary_count);
			if (error != 0)
				break;
			continue;
		}

		stream = dent->stream;
		name_len = stream.se_name_length;
		name_hash = le16toh(stream.se_name_hash);
		num_name_entries = howmany(name_len,
		    EXFAT_CHARS_PER_NAME_ENTRY);

		/* Check if hash and length match target */
		if (name_len != target_nchars || name_len == 0 ||
		    secondary_count < 1 + num_name_entries ||
		    name_hash != target_hash) {
			error = exfat_dir_cursor_skip(&dc, secondary_count);
			if (error != 0)
				break;
			continue;
		}

		/*
		 * Candidate match: compute checksum of primary and stream
		 * entries, then read file name entries.
		 */
		cs = exfat_entry_checksum(prim_dent.raw, 0, true);
		cs = exfat_entry_checksum(dent->raw, cs, false);
		chars_read = 0;
		valid_set = true;

		for (sec_idx = 1; sec_idx < secondary_count; sec_idx++) {
			error = exfat_dir_cursor_next(&dc);
			if (error != 0)
				break;

			error = exfat_dir_cursor_get(&dc, &dent, NULL, NULL);
			if (error != 0)
				break;

			if (sec_idx <= num_name_entries) {
				size_t to_copy;

				if (dent->type != EXFAT_ENTRY_NAME) {
					valid_set = false;
					break;
				}
				to_copy = name_len - chars_read;
				if (to_copy > EXFAT_CHARS_PER_NAME_ENTRY)
					to_copy = EXFAT_CHARS_PER_NAME_ENTRY;

				for (size_t k = 0; k < to_copy; k++)
					file_utf16[chars_read + k] =
					    le16toh(dent->name.ne_file_name[k]);
				chars_read += to_copy;
			} else if ((dent->type & (EXFAT_ENTRY_TYPE_IN_USE |
			    EXFAT_ENTRY_TYPE_SECONDARY |
			    EXFAT_ENTRY_TYPE_BENIGN)) !=
			    (EXFAT_ENTRY_TYPE_IN_USE |
			    EXFAT_ENTRY_TYPE_SECONDARY |
			    EXFAT_ENTRY_TYPE_BENIGN)) {
				/*
				 * Trailing secondary entries (e.g. Vendor
				 * Extension 0xE0 or Vendor Allocation 0xE1
				 * per Spec §7.8/§7.9) must be in-use benign
				 * secondary entries per Spec §6.2.1 and
				 * §6.4.1.2.2.
				 */
				valid_set = false;
				break;
			}
			cs = exfat_entry_checksum(dent->raw, cs, false);
		}

		if (error != 0)
			break;
		if (!valid_set) {
			error = exfat_dir_cursor_skip(&dc,
			    secondary_count - sec_idx);
			if (error != 0)
				break;
			continue;
		}

		/*
		 * Verify SetChecksum (Spec §6.3.3 / §7.4.3). Implementations
		 * shall verify the checksum is valid before trusting or using
		 * any other directory entry in the set; omitting this check is
		 * a specification compliance defect.
		 */
		if (chars_read == target_nchars && cs == set_checksum &&
		    exfat_case_compare(pmp, file_utf16, target_utf16,
		    target_nchars)) {
			exfat_dir_cursor_put(&dc);

			if ((cnp->cn_nameiop == DELETE ||
			    cnp->cn_nameiop == RENAME) &&
			    (cnp->cn_flags & ISLASTCN) != 0) {
				error = VOP_ACCESS(vdp, VWRITE, cnp->cn_cred,
				    curthread);
				if (error != 0)
					return (error);
			}

			error = exfat_node_get(pmp, prim_cluster,
			    prim_offset, cnp->cn_lkflags, &np);
			if (error != 0)
				return (error);

			np->node_parent_dirclust = dp->node_dirclust;
			np->node_parent_diroffset = dp->node_diroffset;

			if ((cnp->cn_flags & MAKEENTRY) != 0)
				cache_enter(vdp, NODETOV(np), cnp);

			if (vpp != NULL)
				*vpp = NODETOV(np);
			return (0);
		}

		/* Advance to the entry after this set */
		error = exfat_dir_cursor_next(&dc);
		if (error != 0)
			break;
	}

	exfat_dir_cursor_put(&dc);

	if (error != 0 && error != ENOENT)
		return (error);

	if ((cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME) &&
	    (cnp->cn_flags & ISLASTCN)) {
		error = VOP_ACCESS(vdp, VWRITE, cnp->cn_cred, curthread);
		if (error != 0)
			return (error);
		return (EJUSTRETURN);
	}

	if ((cnp->cn_flags & MAKEENTRY) != 0)
		cache_enter(vdp, NULL, cnp);

	return (ENOENT);
}

/*
 * Virtual directory offset where real on-disk directory entries begin in
 * exfat_readdir(), reserving virtual offsets 0 and EXFAT_DENTRY_SIZE for
 * the synthetic "." and ".." entries.
 */
#define EXFAT_DIR_START_OFFSET	(2 * EXFAT_DENTRY_SIZE)

static int
exfat_readdir(struct vop_readdir_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct exfat_node *dp = VTONODE(vp);
	struct exfat_mount *pmp = dp->node_pmp;
	struct dirent dirbuf;
	struct exfat_dir_cursor dc;
	uint64_t *cookies = NULL;
	off_t offset;
	ssize_t orig_resid;
	uint32_t disk_offset;
	int error = 0;
	int ncookies = 0, ncookies_used = 0;

	if (ap->a_eofflag != NULL)
		*ap->a_eofflag = 0;

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	if ((dp->node_flag & EXFAT_NODE_UNLINKED) != 0) {
		if (ap->a_eofflag != NULL)
			*ap->a_eofflag = 1;
		return (0);
	}

	offset = uio->uio_offset;
	if (offset < 0 || (offset & (sizeof(union exfat_dentry) - 1)) != 0)
		return (EINVAL);

	orig_resid = uio->uio_resid;

	if (ap->a_ncookies != NULL) {
		ncookies = uio->uio_resid / 16;
		if (ncookies < 16)
			ncookies = 16;
		cookies = malloc(ncookies * sizeof(*cookies), M_TEMP, M_WAITOK);
	}

	/* Entry 0: "." */
	if (offset == 0) {
		memset(&dirbuf, 0, sizeof(dirbuf));
		dirbuf.d_fileno = dp->node_inode;
		dirbuf.d_type = DT_DIR;
		dirbuf.d_namlen = 1;
		dirbuf.d_name[0] = '.';
		dirbuf.d_name[1] = '\0';
		dirbuf.d_off = EXFAT_DENTRY_SIZE;
		dirbuf.d_reclen = GENERIC_DIRSIZ(&dirbuf);
		dirent_terminate(&dirbuf);

		if (uio->uio_resid < dirbuf.d_reclen)
			goto out;

		error = uiomove(&dirbuf, dirbuf.d_reclen, uio);
		if (error != 0)
			goto out;

		offset = EXFAT_DENTRY_SIZE;
		if (cookies != NULL) {
			cookies[ncookies_used++] = offset;
			if (ncookies_used >= ncookies)
				goto out;
		}
	}

	/* Entry 1: ".." */
	if (offset == EXFAT_DENTRY_SIZE) {
		memset(&dirbuf, 0, sizeof(dirbuf));
		if (vp->v_vflag & VV_ROOT)
			dirbuf.d_fileno = dp->node_inode;
		else
			dirbuf.d_fileno = exfat_make_inode(
			    dp->node_parent_dirclust,
			    dp->node_parent_diroffset);
		dirbuf.d_type = DT_DIR;
		dirbuf.d_namlen = 2;
		dirbuf.d_name[0] = '.';
		dirbuf.d_name[1] = '.';
		dirbuf.d_name[2] = '\0';
		dirbuf.d_off = EXFAT_DIR_START_OFFSET;
		dirbuf.d_reclen = GENERIC_DIRSIZ(&dirbuf);
		dirent_terminate(&dirbuf);

		if (uio->uio_resid < dirbuf.d_reclen)
			goto out;

		error = uiomove(&dirbuf, dirbuf.d_reclen, uio);
		if (error != 0)
			goto out;

		offset = EXFAT_DIR_START_OFFSET;
		if (cookies != NULL) {
			cookies[ncookies_used++] = offset;
			if (ncookies_used >= ncookies)
				goto out;
		}
	}

	/* On-disk directory entries: offset >= EXFAT_DIR_START_OFFSET */
	disk_offset = (offset >= EXFAT_DIR_START_OFFSET) ?
	    (uint32_t)(offset - EXFAT_DIR_START_OFFSET) : 0;
	error = exfat_dir_cursor_seek(pmp, dp, &dc, disk_offset);
	if (error != 0) {
		if (error == ENOENT) {
			/* Past end of directory */
			if (ap->a_eofflag != NULL)
				*ap->a_eofflag = 1;
			error = 0;
		}
		goto out;
	}

	while (1) {
		const union exfat_dentry *dent;
		struct exfat_dentry_file fe;
		struct exfat_dentry_stream stream;
		uint16_t file_utf16[EXFAT_MAX_NAME_CHARS];
		size_t chars_read, num_name_entries;
		uint32_t cur_disk_off, prim_cluster, prim_offset;
		uint16_t cs, set_checksum;
		uint8_t name_len, sec_idx, secondary_count;
		bool valid_set;

		cur_disk_off = disk_offset;

		error = exfat_dir_cursor_get(&dc, &dent, &prim_cluster,
		    &prim_offset);
		if (error != 0) {
			if (error == ENOENT) {
				offset = EXFAT_DIR_START_OFFSET + disk_offset;
				if (ap->a_eofflag != NULL)
					*ap->a_eofflag = 1;
				error = 0;
			}
			break;
		}

		if (dent->type == EXFAT_ENTRY_EOD) {
			offset = EXFAT_DIR_START_OFFSET + disk_offset;
			if (ap->a_eofflag != NULL)
				*ap->a_eofflag = 1;
			break;
		}

		if ((dent->type & EXFAT_ENTRY_TYPE_IN_USE) == 0 ||
		    dent->type != EXFAT_ENTRY_FILE) {
			error = exfat_dir_cursor_next(&dc);
			if (error != 0)
				break;
			disk_offset += sizeof(union exfat_dentry);
			continue;
		}

		/* Primary file entry (0x85) */
		fe = dent->file;
		secondary_count = fe.fe_secondary_count;

		if (secondary_count < EXFAT_MIN_SECONDARY_COUNT ||
		    secondary_count > EXFAT_MAX_SECONDARY_COUNT) {
			error = exfat_dir_cursor_next(&dc);
			if (error != 0)
				break;
			disk_offset += sizeof(union exfat_dentry);
			continue;
		}
		set_checksum = le16toh(fe.fe_set_checksum);
		cs = exfat_entry_checksum(dent->raw, 0, true);

		/* Advance to Stream Extension entry (0xC0) */
		error = exfat_dir_cursor_next(&dc);
		if (error != 0)
			break;
		disk_offset += sizeof(union exfat_dentry);

		error = exfat_dir_cursor_get(&dc, &dent, NULL, NULL);
		if (error != 0)
			break;

		if (dent->type != EXFAT_ENTRY_STREAM) {
			error = exfat_dir_cursor_skip(&dc, secondary_count);
			if (error != 0)
				break;
			disk_offset += secondary_count *
			    sizeof(union exfat_dentry);
			continue;
		}

		stream = dent->stream;
		name_len = stream.se_name_length;
		num_name_entries = howmany(name_len,
		    EXFAT_CHARS_PER_NAME_ENTRY);

		if (secondary_count < 1 + num_name_entries || name_len == 0) {
			error = exfat_dir_cursor_skip(&dc, secondary_count);
			if (error != 0)
				break;
			disk_offset += secondary_count *
			    sizeof(union exfat_dentry);
			continue;
		}

		cs = exfat_entry_checksum(dent->raw, cs, false);
		chars_read = 0;
		valid_set = true;

		for (sec_idx = 1; sec_idx < secondary_count; sec_idx++) {
			error = exfat_dir_cursor_next(&dc);
			if (error != 0)
				break;
			disk_offset += sizeof(union exfat_dentry);

			error = exfat_dir_cursor_get(&dc, &dent, NULL, NULL);
			if (error != 0)
				break;

			if (sec_idx <= num_name_entries) {
				size_t to_copy;

				if (dent->type != EXFAT_ENTRY_NAME) {
					valid_set = false;
					break;
				}
				to_copy = name_len - chars_read;
				if (to_copy > EXFAT_CHARS_PER_NAME_ENTRY)
					to_copy = EXFAT_CHARS_PER_NAME_ENTRY;

				for (size_t k = 0; k < to_copy; k++)
					file_utf16[chars_read + k] =
					    le16toh(dent->name.ne_file_name[k]);
				chars_read += to_copy;
			} else if ((dent->type & (EXFAT_ENTRY_TYPE_IN_USE |
			    EXFAT_ENTRY_TYPE_SECONDARY |
			    EXFAT_ENTRY_TYPE_BENIGN)) !=
			    (EXFAT_ENTRY_TYPE_IN_USE |
			    EXFAT_ENTRY_TYPE_SECONDARY |
			    EXFAT_ENTRY_TYPE_BENIGN)) {
				/*
				 * Trailing secondary entries (e.g. Vendor
				 * Extension 0xE0 or Vendor Allocation 0xE1
				 * per Spec §7.8/§7.9) must be in-use benign
				 * secondary entries per Spec §6.2.1 and
				 * §6.4.1.2.2.
				 */
				valid_set = false;
				break;
			}
			cs = exfat_entry_checksum(dent->raw, cs, false);
		}

		if (error != 0)
			break;
		if (!valid_set) {
			error = exfat_dir_cursor_skip(&dc,
			    secondary_count - sec_idx);
			if (error != 0)
				break;
			disk_offset += (secondary_count - sec_idx) *
			    sizeof(union exfat_dentry);
			continue;
		}

		/*
		 * Verify SetChecksum (Spec §6.3.3 / §7.4.3). Implementations
		 * shall verify the checksum is valid before trusting or using
		 * any other directory entry in the set; omitting this check is
		 * a specification compliance defect.
		 */
		if (chars_read == name_len && cs == set_checksum) {
			off_t next_off;

			memset(&dirbuf, 0, sizeof(dirbuf));
			dirbuf.d_fileno = exfat_make_inode(prim_cluster,
			    prim_offset);
			dirbuf.d_type = (le16toh(fe.fe_file_attributes) &
			    EXFAT_ATTR_DIRECTORY) ? DT_DIR : DT_REG;

			exfat_utf16_to_utf8(file_utf16, chars_read,
			    dirbuf.d_name, sizeof(dirbuf.d_name));
			dirbuf.d_namlen = strlen(dirbuf.d_name);

			next_off = EXFAT_DIR_START_OFFSET + cur_disk_off +
			    (1 + secondary_count) * sizeof(union exfat_dentry);
			dirbuf.d_off = next_off;
			dirbuf.d_reclen = GENERIC_DIRSIZ(&dirbuf);
			dirent_terminate(&dirbuf);

			if (uio->uio_resid < dirbuf.d_reclen) {
				offset = EXFAT_DIR_START_OFFSET + cur_disk_off;
				break;
			}

			error = uiomove(&dirbuf, dirbuf.d_reclen, uio);
			if (error != 0)
				break;

			offset = next_off;
			if (cookies != NULL) {
				cookies[ncookies_used++] = offset;
				if (ncookies_used >= ncookies)
					break;
			}
		}

		/* Advance past the last secondary entry to the next entry */
		error = exfat_dir_cursor_next(&dc);
		if (error != 0)
			break;
		disk_offset += sizeof(union exfat_dentry);
	}

	if (error == ENOENT) {
		offset = EXFAT_DIR_START_OFFSET + disk_offset;
		if (ap->a_eofflag != NULL)
			*ap->a_eofflag = 1;
		error = 0;
	}

	exfat_dir_cursor_put(&dc);

out:
	if (ap->a_ncookies != NULL) {
		if (error != 0) {
			free(cookies, M_TEMP);
			*ap->a_cookies = NULL;
			*ap->a_ncookies = 0;
		} else {
			*ap->a_ncookies = ncookies_used;
			*ap->a_cookies = cookies;
		}
	}

	uio->uio_offset = offset;
	if (uio->uio_resid < orig_resid &&
	    (vp->v_mount->mnt_flag & (MNT_NOATIME | MNT_RDONLY)) == 0)
		dp->node_flag |= EXFAT_NODE_ATIME;

	return (error);
}

/*
 * Create a new directory entry set and instantiate an exFAT node.
 *
 * Validates the component name, converts to UTF-16, computes the 16-bit
 * NameHash per Spec §7.6.4, finds a contiguous slot of entries in directory
 * vdp with exfat_dentry_find_free_slot(), populates the primary File
 * Directory Entry (0x85), Stream Extension Entry (0xC0), and File Name
 * Entries (0xC1), computes the SetChecksum, and writes the set to disk with
 * exfat_dentry_write_set().  Instantiates the vnode via exfat_node_get().
 *
 * Stores the newly created, locked vnode in *vpp.
 * Returns 0 on success, or an error code from allocation, validation, or I/O.
 */
static int
exfat_makeentry(struct vnode *vdp, struct vnode **vpp,
    struct componentname *cnp, __enum_uint8(vtype) target_type)
{
	struct exfat_node *dp = VTONODE(vdp);
	struct exfat_mount *pmp = dp->node_pmp;
	struct exfat_node *np;
	uint16_t name_utf16[EXFAT_MAX_NAME_CHARS];
	size_t name_nchars;
	uint16_t name_hash;
	uint8_t num_name_entries, total_entries;
	uint32_t slot_cluster, slot_offset, dir_first_cn = 0;
	uint64_t data_len = 0, valid_len = 0;
	uint16_t attrs;
	uint8_t stream_flags;
	union exfat_dentry *dentries;
	struct timespec ts;
	uint16_t date, time;
	uint8_t hun, tz;
	struct buf *bp;
	int error;

	if (vdp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	if ((dp->node_flag & EXFAT_NODE_UNLINKED) != 0)
		return (ENOENT);

	error = exfat_utf8_to_utf16(cnp->cn_nameptr, cnp->cn_namelen,
	    name_utf16, EXFAT_MAX_NAME_CHARS, &name_nchars);
	if (error != 0)
		return (error);

	if (!exfat_is_valid_name(name_utf16, name_nchars))
		return (EINVAL);

	name_hash = exfat_name_hash(pmp, name_utf16, name_nchars);

	num_name_entries = howmany(name_nchars, EXFAT_CHARS_PER_NAME_ENTRY);
	total_entries = 2 + num_name_entries;

	if (target_type == VDIR) {
		bool contig;
		error = exfat_bitmap_alloc_clusters(pmp, 1, &dir_first_cn,
		    &contig);
		if (error != 0)
			return (error);

		/* Zero out directory cluster in core */
		bp = getblk(pmp->pm_devvp, exfat_cntodaddr(pmp, dir_first_cn),
		    pmp->pm_cluster_size, 0, 0, 0);
		vfs_bio_clrbuf(bp);
		bdwrite(bp);

		data_len = pmp->pm_cluster_size;
		valid_len = pmp->pm_cluster_size;
		attrs = EXFAT_ATTR_DIRECTORY;
		stream_flags = EXFAT_FLAG_ALLOC_POSSIBLE |
		    EXFAT_FLAG_NO_FAT_CHAIN;
	} else {
		attrs = EXFAT_ATTR_ARCHIVE;
		stream_flags = EXFAT_FLAG_ALLOC_POSSIBLE;
	}

	error = exfat_dentry_find_free_slot(dp, total_entries, &slot_cluster,
	    &slot_offset);
	if (error != 0) {
		if (target_type == VDIR)
			exfat_bitmap_free_clusters(pmp, dir_first_cn, 1);
		return (error);
	}

	dentries = malloc(total_entries * sizeof(union exfat_dentry),
	    M_TEMP, M_WAITOK | M_ZERO);

	vfs_timestamp(&ts);
	timespec2fattime(&ts, 0, &date, &time, &hun);
	tz = exfat_tz_offset();

	/* 1. Primary File Entry */
	dentries[0].file.fe_type = EXFAT_ENTRY_FILE;
	dentries[0].file.fe_secondary_count = 1 + num_name_entries;
	dentries[0].file.fe_file_attributes = htole16(attrs);
	dentries[0].file.fe_create_timestamp =
	    htole32(((uint32_t)date << 16) | time);
	dentries[0].file.fe_last_modified_timestamp =
	    dentries[0].file.fe_create_timestamp;
	dentries[0].file.fe_last_access_timestamp =
	    dentries[0].file.fe_create_timestamp;
	dentries[0].file.fe_create_10ms_increment = hun;
	dentries[0].file.fe_last_modified_10ms_increment = hun;
	dentries[0].file.fe_create_tz_offset = tz;
	dentries[0].file.fe_last_modified_tz_offset = tz;
	dentries[0].file.fe_last_access_tz_offset = tz;

	/* 2. Stream Extension Entry */
	dentries[1].stream.se_type = EXFAT_ENTRY_STREAM;
	dentries[1].stream.se_general_flags = stream_flags;
	dentries[1].stream.se_name_length = name_nchars;
	dentries[1].stream.se_name_hash = htole16(name_hash);
	dentries[1].stream.se_first_cluster = htole32(dir_first_cn);
	dentries[1].stream.se_data_length = htole64(data_len);
	dentries[1].stream.se_valid_data_length = htole64(valid_len);

	/* 3. File Name Entries */
	for (uint8_t n = 0; n < num_name_entries; n++) {
		struct exfat_dentry_name *ne = &dentries[2 + n].name;
		ne->ne_type = EXFAT_ENTRY_NAME;
		for (size_t c = 0; c < EXFAT_CHARS_PER_NAME_ENTRY; c++) {
			size_t src_idx = n * EXFAT_CHARS_PER_NAME_ENTRY + c;
			if (src_idx < name_nchars)
				ne->ne_file_name[c] =
				    htole16(name_utf16[src_idx]);
			else
				ne->ne_file_name[c] = 0;
		}
	}

	/* Calculate set checksum */
	exfat_dentry_set_checksum(dentries, total_entries);

	/* Write entry set to disk (handling cross-cluster sets) */
	error = exfat_dentry_write_set(pmp, dp, slot_cluster, slot_offset,
	    dentries, total_entries);
	free(dentries, M_TEMP);
	if (error != 0) {
		dp->node_dir_hint_clust = slot_cluster;
		dp->node_dir_hint_offset = slot_offset;
		(void)exfat_dir_shrink(dp);
		if (target_type == VDIR)
			exfat_bitmap_free_clusters(pmp, dir_first_cn, 1);
		return (error);
	}

	/* Obtain node for the newly created file/directory */
	error = exfat_node_get(pmp, slot_cluster, slot_offset,
	    cnp->cn_lkflags, &np);
	if (error != 0) {
		(void)exfat_dentry_delete_set(pmp, dp, slot_cluster,
		    slot_offset, total_entries);
		dp->node_dir_hint_clust = slot_cluster;
		dp->node_dir_hint_offset = slot_offset;
		(void)exfat_dir_shrink(dp);
		if (target_type == VDIR)
			exfat_bitmap_free_clusters(pmp, dir_first_cn, 1);
		return (error);
	}

	np->node_attributes = attrs;
	np->node_first_cluster = dir_first_cn;
	np->node_size = data_len;
	np->node_valid_size = valid_len;
	np->node_stream_flags = stream_flags;
	np->node_secondary_count = 1 + num_name_entries;
	np->node_ctime = ((uint32_t)date << 16) | time;
	np->node_mtime = np->node_ctime;
	np->node_atime = np->node_ctime;
	np->node_c_10ms = hun;
	np->node_m_10ms = hun;
	np->node_c_tz = tz;
	np->node_m_tz = tz;
	np->node_a_tz = tz;
	np->node_parent_dirclust = dp->node_dirclust;
	np->node_parent_diroffset = dp->node_diroffset;

	if (target_type == VDIR) {
		np->node_dir_hint_clust = dir_first_cn;
		np->node_dir_hint_offset = 0;
	}

	NODETOV(np)->v_type = target_type;

	dp->node_flag |= EXFAT_NODE_MTIME | EXFAT_NODE_DIRTY;
	cache_purge_negative(vdp);
	if ((cnp->cn_flags & MAKEENTRY) != 0)
		cache_enter(vdp, NODETOV(np), cnp);

	*vpp = NODETOV(np);
	return (0);
}

static int
exfat_create(struct vop_create_args *ap)
{
	return (exfat_makeentry(ap->a_dvp, ap->a_vpp, ap->a_cnp, VREG));
}

static int
exfat_mkdir(struct vop_mkdir_args *ap)
{
	return (exfat_makeentry(ap->a_dvp, ap->a_vpp, ap->a_cnp, VDIR));
}

static int
exfat_remove(struct vop_remove_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	struct exfat_node *dp = VTONODE(ap->a_dvp);
	struct exfat_mount *pmp = np->node_pmp;
	int error;

	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	if (vp->v_type == VDIR)
		return (EPERM);

	if ((dp->node_flag & EXFAT_NODE_UNLINKED) != 0 ||
	    (np->node_flag & EXFAT_NODE_UNLINKED) != 0)
		return (ENOENT);

	error = exfat_dentry_delete_set(pmp, dp, np->node_dirclust,
	    np->node_diroffset, 1 + np->node_secondary_count);
	if (error != 0)
		return (error);

	dp->node_dir_hint_clust = np->node_dirclust;
	dp->node_dir_hint_offset = np->node_diroffset;
	dp->node_flag |= EXFAT_NODE_MTIME | EXFAT_NODE_DIRTY;
	/* Best-effort shrinkage of trailing empty directory clusters. */
	(void)exfat_dir_shrink(dp);

	np->node_flag |= EXFAT_NODE_UNLINKED;

	cache_purge(vp);
	return (0);
}

static int
exfat_rmdir(struct vop_rmdir_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	struct exfat_node *dp = VTONODE(ap->a_dvp);
	struct exfat_mount *pmp = np->node_pmp;
	int error;

	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	if ((dp->node_flag & EXFAT_NODE_UNLINKED) != 0 ||
	    (np->node_flag & EXFAT_NODE_UNLINKED) != 0)
		return (ENOENT);

	error = exfat_dir_is_empty(np);
	if (error != 0)
		return (error);

	error = exfat_dentry_delete_set(pmp, dp, np->node_dirclust,
	    np->node_diroffset, 1 + np->node_secondary_count);
	if (error != 0)
		return (error);

	dp->node_dir_hint_clust = np->node_dirclust;
	dp->node_dir_hint_offset = np->node_diroffset;
	dp->node_flag |= EXFAT_NODE_MTIME | EXFAT_NODE_DIRTY;
	/* Best-effort shrinkage of trailing empty directory clusters. */
	(void)exfat_dir_shrink(dp);

	np->node_flag |= EXFAT_NODE_UNLINKED;

	cache_purge(vp);
	return (0);
}

/*
 * Check whether a directory subtree contains a target cluster.
 *
 * Recursively scans directory clusters starting at dir_cn down to a maximum
 * recursion depth of 64.  For each sub-directory entry discovered, checks
 * whether its cluster chain contains target_cn, recursing into
 * subdirectories.  Releases buffer cache locks before descending to avoid
 * deadlock on corrupt cyclic directory links.
 *
 * Returns true if target_cn was found in the directory hierarchy, false
 * otherwise.
 */
static bool
exfat_dir_contains_cluster(struct exfat_mount *pmp, uint32_t dir_cn,
    uint8_t stream_flags, uint64_t dir_size, uint32_t target_cn, int depth)
{
	struct exfat_node tmp_dp;
	struct exfat_dir_cursor dc;
	const union exfat_dentry *dent;
	uint32_t prim_cluster, prim_offset;
	int error;

	if (depth > 64 || !EXFAT_CLUSTER_VALID(pmp, dir_cn) ||
	    !EXFAT_CLUSTER_VALID(pmp, target_cn))
		return (false);

	if (exfat_cluster_in_chain(pmp, dir_cn, stream_flags, dir_size,
	    target_cn))
		return (true);

	memset(&tmp_dp, 0, sizeof(tmp_dp));
	tmp_dp.node_pmp = pmp;
	tmp_dp.node_dirclust = dir_cn;
	tmp_dp.node_diroffset = 0;
	tmp_dp.node_first_cluster = dir_cn;
	tmp_dp.node_stream_flags = stream_flags;
	tmp_dp.node_size = dir_size;
	tmp_dp.node_attributes = EXFAT_ATTR_DIRECTORY;

	exfat_dir_cursor_init(pmp, &tmp_dp, &dc);
	while (exfat_dir_cursor_get(&dc, &dent, &prim_cluster,
	    &prim_offset) == 0) {
		if (dent->type == EXFAT_ENTRY_EOD)
			break;
		if (dent->type == EXFAT_ENTRY_FILE) {
			uint8_t sec_count = dent->file.fe_secondary_count;

			if (sec_count < EXFAT_MIN_SECONDARY_COUNT ||
			    sec_count > EXFAT_MAX_SECONDARY_COUNT) {
				if (exfat_dir_cursor_next(&dc) != 0)
					break;
				continue;
			}

			if ((le16toh(dent->file.fe_file_attributes) &
			    EXFAT_ATTR_DIRECTORY) != 0) {
				uint32_t sub_cn;
				uint8_t sub_flags;
				uint64_t sub_size;

				error = exfat_dir_cursor_next(&dc);
				if (error != 0)
					break;
				error = exfat_dir_cursor_get(&dc, &dent,
				    NULL, NULL);
				if (error != 0)
					break;
				if (dent->type == EXFAT_ENTRY_STREAM) {
					sub_cn = le32toh(
					    dent->stream.se_first_cluster);
					sub_flags =
					    dent->stream.se_general_flags;
					sub_size = le64toh(
					    dent->stream.se_data_length);

					/*
					 * Release the directory cluster buffer
					 * before recursing so a corrupted
					 * directory cycle cannot deadlock on a
					 * buffer we already hold.
					 */
					exfat_dir_cursor_put(&dc);
					if (EXFAT_CLUSTER_VALID(pmp, sub_cn) &&
					    (sub_cn == target_cn ||
					    exfat_dir_contains_cluster(pmp,
					    sub_cn, sub_flags, sub_size,
					    target_cn, depth + 1)))
						return (true);
				}
				error = exfat_dir_cursor_skip(&dc, sec_count);
				if (error != 0)
					break;
				continue;
			}

			/* Skip secondary entries of regular files. */
			error = exfat_dir_cursor_skip(&dc, sec_count);
			if (error != 0)
				break;
		}
		error = exfat_dir_cursor_next(&dc);
		if (error != 0)
			break;
	}
	exfat_dir_cursor_put(&dc);
	return (false);
}

/*
 * Validate directory rename path to prevent cyclic ancestor-descendant moves.
 *
 * Ascends the parent directory chain from target back to the root directory
 * to ensure that source is not an ancestor of target.  If any directory along
 * the path is uncached in memory, loads its entry set from disk to discover
 * its parent.  Falls back to exfat_dir_contains_cluster() for deep or
 * unresolvable paths.
 *
 * Returns 0 if the rename path is valid, EINVAL if source is an ancestor of
 * target (preventing directory cycle creation), or an I/O error.
 */
static int
exfat_checkpath(struct exfat_node *source, struct exfat_node *target,
    struct exfat_node *fdp)
{
	union exfat_dentry dset[EXFAT_MAX_ENTRY_SET];
	struct exfat_mount *pmp;
	struct exfat_node *curr;
	struct vnode *pvp;
	uint64_t pinode;
	uint32_t child_dirclust, child_first_cn;
	uint32_t next_p_clust, next_p_offset, p_dirclust, p_diroffset;
	uint32_t p_first_cn, loop_count = 0;
	int error;

	if (source == NULL || target == NULL)
		return (EINVAL);

	pmp = source->node_pmp;

	/* Cannot move a directory into itself */
	if (target == source ||
	    (EXFAT_CLUSTER_VALID(pmp, source->node_first_cluster) &&
	    EXFAT_CLUSTER_VALID(pmp, target->node_first_cluster) &&
	    target->node_first_cluster == source->node_first_cluster))
		return (EINVAL);

	/* If target is root directory, it cannot be inside source */
	if (EXFAT_IS_ROOT(target->node_dirclust, target->node_diroffset))
		return (0);

	/* Check if target resides directly in source's cluster chain */
	if (exfat_cluster_in_chain(pmp, source->node_first_cluster,
	    source->node_stream_flags, source->node_size,
	    target->node_dirclust))
		return (EINVAL);

	if (EXFAT_CLUSTER_VALID(pmp, target->node_first_cluster) &&
	    exfat_cluster_in_chain(pmp, source->node_first_cluster,
	    source->node_stream_flags, source->node_size,
	    target->node_first_cluster))
		return (EINVAL);

	child_dirclust = target->node_dirclust;
	child_first_cn = target->node_first_cluster;
	p_dirclust = target->node_parent_dirclust;
	p_diroffset = target->node_parent_diroffset;
	for (;;) {
		if (++loop_count > pmp->pm_cluster_count)
			return (ELOOP);

		/* Parent locator matches source's locator */
		if (p_dirclust == source->node_dirclust &&
		    p_diroffset == source->node_diroffset)
			return (EINVAL);

		/*
		 * A parent locator of (0, 0) means either the child is a
		 * direct entry in the root directory, or the child vnode was
		 * instantiated via exfat_fhtovp() without a known parent.
		 */
		if (EXFAT_IS_ROOT(p_dirclust, p_diroffset)) {
			if (exfat_cluster_in_chain(pmp, pmp->pm_rootdir_cluster,
			    0, 0, child_dirclust))
				return (0);
			if ((EXFAT_CLUSTER_VALID(pmp, child_dirclust) &&
			    exfat_dir_contains_cluster(pmp,
			    source->node_first_cluster,
			    source->node_stream_flags, source->node_size,
			    child_dirclust, 0)) ||
			    (EXFAT_CLUSTER_VALID(pmp, child_first_cn) &&
			    exfat_dir_contains_cluster(pmp,
			    source->node_first_cluster,
			    source->node_stream_flags, source->node_size,
			    child_first_cn, 0)))
				return (EINVAL);
			return (0);
		}
		if (exfat_cluster_in_chain(pmp, pmp->pm_rootdir_cluster, 0, 0,
		    p_dirclust))
			return (0);

		/* Parent cluster is within source's cluster chain */
		if (exfat_cluster_in_chain(pmp, source->node_first_cluster,
		    source->node_stream_flags, source->node_size, p_dirclust))
			return (EINVAL);

		/* Check if parent is source's parent (fdp) */
		pinode = exfat_make_inode(p_dirclust, p_diroffset);
		if (pinode == source->node_inode)
			return (EINVAL);
		if (pinode == fdp->node_inode)
			return (0);

		/* Try looking up parent vnode in active hash */
		vfs_hash_ref(pmp->pm_mountp, exfat_vnode_hash(pinode),
		    curthread, &pvp, exfat_vncmpf, &pinode);
		if (pvp != NULL) {
			uint32_t curr_first_cn, curr_dirclust, curr_diroffset;

			VI_LOCK(pvp);
			if (pvp->v_type == VNON) {
				VI_UNLOCK(pvp);
				vrele(pvp);
				break;
			}
			curr = VTONODE(pvp);
			if (curr == NULL) {
				VI_UNLOCK(pvp);
				vrele(pvp);
				break;
			}
			curr_first_cn = curr->node_first_cluster;
			curr_dirclust = curr->node_dirclust;
			curr_diroffset = curr->node_diroffset;
			next_p_clust = curr->node_parent_dirclust;
			next_p_offset = curr->node_parent_diroffset;
			VI_UNLOCK(pvp);
			vrele(pvp);

			if (curr == source ||
			    (EXFAT_CLUSTER_VALID(pmp,
			    source->node_first_cluster) &&
			    curr_first_cn == source->node_first_cluster))
				return (EINVAL);

			if (EXFAT_IS_ROOT(curr_dirclust, curr_diroffset))
				return (0);

			if (exfat_cluster_in_chain(pmp,
			    source->node_first_cluster,
			    source->node_stream_flags, source->node_size,
			    curr_dirclust))
				return (EINVAL);

			child_dirclust = curr_dirclust;
			child_first_cn = curr_first_cn;
			p_dirclust = next_p_clust;
			p_diroffset = next_p_offset;
			continue;
		}

		/*
		 * If parent is not active in cache, read its on-disk dentry
		 * set to inspect its starting cluster, and scan source's
		 * directory subtree for p_dirclust and p_first_cn.
		 */
		error = exfat_dentry_read_set(pmp, NULL, p_dirclust,
		    p_diroffset, dset, NULL);
		if (error != 0)
			return (error);

		p_first_cn = le32dec(&dset[1].stream.se_first_cluster);

		if (EXFAT_CLUSTER_VALID(pmp, source->node_first_cluster) &&
		    p_first_cn == source->node_first_cluster)
			return (EINVAL);
		if (p_first_cn == pmp->pm_rootdir_cluster)
			return (0);

		if ((EXFAT_CLUSTER_VALID(pmp, p_dirclust) &&
		    exfat_dir_contains_cluster(pmp, source->node_first_cluster,
		    source->node_stream_flags, source->node_size, p_dirclust,
		    0)) ||
		    (EXFAT_CLUSTER_VALID(pmp, p_first_cn) &&
		    exfat_dir_contains_cluster(pmp, source->node_first_cluster,
		    source->node_stream_flags, source->node_size, p_first_cn,
		    0)))
			return (EINVAL);

		break;
	}

	return (0);
}

static int
exfat_rename(struct vop_rename_args *ap)
{
	struct vnode *fdvp = ap->a_fdvp;
	struct vnode *fvp = ap->a_fvp;
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *tvp = ap->a_tvp;
	struct componentname *fcnp = ap->a_fcnp;
	struct componentname *tcnp = ap->a_tcnp;
	struct exfat_node *fdp, *tdp, *tnp;
	struct exfat_node *fnp = VTONODE(fvp);
	struct exfat_mount *pmp = fnp != NULL ? fnp->node_pmp : NULL;
	union exfat_dentry saved_tdset[EXFAT_MAX_ENTRY_SET];
	uint16_t name_utf16[EXFAT_MAX_NAME_CHARS];
	size_t name_nchars;
	uint16_t name_hash;
	uint8_t num_name_entries, total_entries, saved_tcount = 0;
	uint32_t old_dirclust, old_diroffset, slot_cluster, slot_offset;
	uint64_t valid_len;
	union exfat_dentry *dentries;
	/*
	 * Vnode lock-tracking flags for unwind/cleanup at out:.
	 *
	 * When two participating vnodes represent the same underlying vnode
	 * (e.g., fdvp == tdvp for intra-directory renames, or tdvp == tvp):
	 * - Only the primary vnode's lock is tracked and released.
	 * - Specifically, when fdvp == tdvp, the single lock is owned and
	 *   released by tdvp (via vput(tdvp)); fdvp_locked tracks only an
	 *   independent, separate lock on fdvp when fdvp != tdvp and must
	 *   remain false when fdvp == tdvp to prevent double-unlocking.
	 * - Similarly, if tdvp == tvp, out: releases the shared lock via
	 *   tvp rather than both.
	 */
	bool fdvp_locked = false, fvp_locked = false;
	bool tvp_locked = (tvp != NULL);
	int error = 0;

	if (fvp->v_mount->mnt_flag & MNT_RDONLY) {
		error = EROFS;
		goto out;
	}

	if (fvp->v_mount != tdvp->v_mount ||
	    (tvp != NULL && fvp->v_mount != tvp->v_mount)) {
		error = EXDEV;
		goto out;
	}

	if ((ap->a_flags & ~AT_RENAME_NOREPLACE) != 0) {
		error = EOPNOTSUPP;
		goto out;
	}

	if (fvp == tvp) {
		error = 0;
		goto out;
	}

	if (tvp != NULL && (ap->a_flags & AT_RENAME_NOREPLACE) != 0) {
		error = EEXIST;
		goto out;
	}

	/*
	 * Reject renaming ".", "..", the root directory, a directory into
	 * itself (fvp == tdvp), or a child over its parent directory
	 * (fdvp == tvp) before acquiring additional vnode locks.
	 */
	if ((fvp->v_vflag & VV_ROOT) != 0 ||
	    fnp == NULL ||
	    EXFAT_IS_ROOT(fnp->node_dirclust, fnp->node_diroffset) ||
	    fdvp == fvp || fvp == tdvp ||
	    (fcnp->cn_namelen == 1 && fcnp->cn_nameptr[0] == '.') ||
	    ((fcnp->cn_flags | tcnp->cn_flags) & ISDOTDOT) != 0) {
		error = EINVAL;
		goto out;
	}

	if (tdvp == tvp ||
	    (tcnp->cn_namelen == 1 && tcnp->cn_nameptr[0] == '.')) {
		error = (fvp->v_type == VDIR) ? EINVAL : EISDIR;
		goto out;
	}

	if (fdvp == tvp) {
		error = (fvp->v_type == VDIR) ? ENOTEMPTY : EISDIR;
		goto out;
	}

	/*
	 * Vnode Locking Strategy in exfat_rename():
	 *
	 * VOP_RENAME enters with tdvp and tvp (if non-NULL) locked, while
	 * fdvp and fvp are unlocked.  Atomic directory tree mutation,
	 * source directory shrinking, and inode rehashing require holding
	 * exclusive locks on all participating vnodes (fdvp, tdvp, fvp,
	 * and tvp).
	 *
	 * Acquiring the remaining locks naively via blocking acquisitions
	 * (LK_RETRY) risks lock-order reversal (LOR) deadlocks:
	 * - Contending on fdvp while holding (tdvp, tvp) can deadlock against
	 *   concurrent path traversals between fdvp and tdvp.
	 * - Contending on tvp while holding (fdvp, tdvp) can deadlock if tvp
	 *   is an ancestor of fdvp (e.g. rename("a/b/c", "a")).
	 * - Contending on fvp while holding (fdvp, tdvp, tvp) can deadlock
	 *   if fvp is an ancestor of tdvp (e.g. rename("a", "a/b/c") before
	 *   exfat_checkpath() runs) and a concurrent lookup descends from fvp
	 *   to tdvp following normal parent -> child order.
	 *
	 * We resolve this with a non-blocking fast path and backoff loop:
	 * 1. Fast path: Acquire fdvp (when fdvp != tdvp), tvp (if dropped), and
	 *    fvp with LK_NOWAIT. If uncontested, all locks are established
	 *    without dropping any already-held locks.
	 * 2. If fdvp is contested (which only occurs when fdvp != tdvp): Drop
	 *    tdvp (and tvp if held), then acquire both directories via
	 *    vn_lock_pair(), which enforces deadlock-free dual-directory
	 *    locking with randomized backoff pauses (vn_lock_pair() natively
	 *    handles fdvp == tdvp as a single lock).
	 * 3. If tvp or fvp is contested: Drop all currently held locks,
	 *    perform a blocking lock-and-release cycle on the contested vnode
	 *    (waiting for the holder to finish without holding conflicting
	 *    locks), re-lock (fdvp, tdvp) via vn_lock_pair(), and retry.
	 * 4. Once all vnodes are locked, we verify none are doomed or unlinked,
	 *    and that parent locators did not change while locks were dropped;
	 *    if any vnode shifted, we return ERELOOKUP so the VFS layer can
	 *    re-resolve cleanly.
	 */
	/*
	 * Phase 1: Deadlock-free multi-vnode locking loop.
	 *
	 * Acquire locks on (fdvp, fvp, tdvp, tvp) with non-blocking try-locks
	 * and back-off sleeps without holding contested locks.
	 */
	for (;;) {
		if (fdvp != tdvp && !fdvp_locked) {
			if (vn_lock(fdvp, LK_EXCLUSIVE | LK_NOWAIT) != 0) {
				VOP_UNLOCK(tdvp);
				if (tvp_locked) {
					VOP_UNLOCK(tvp);
					tvp_locked = false;
				}
				vn_lock_pair(fdvp, false, LK_EXCLUSIVE,
				    tdvp, false, LK_EXCLUSIVE);
			}
			fdvp_locked = true;
		}

		if (tvp != NULL && !tvp_locked) {
			if (vn_lock(tvp, LK_EXCLUSIVE | LK_NOWAIT) != 0) {
				if (fdvp != tdvp)
					VOP_UNLOCK(fdvp);
				VOP_UNLOCK(tdvp);
				/*
				 * Sleep without holding any conflicting locks
				 * until the contested vnode becomes free, then
				 * re-lock the directory pair before retrying.
				 */
				vn_lock(tvp, LK_EXCLUSIVE | LK_RETRY);
				VOP_UNLOCK(tvp);
				vn_lock_pair(fdvp, false, LK_EXCLUSIVE,
				    tdvp, false, LK_EXCLUSIVE);
				if (fdvp != tdvp)
					fdvp_locked = true;
				continue;
			}
			tvp_locked = true;
		}

		if (vn_lock(fvp, LK_EXCLUSIVE | LK_NOWAIT) == 0) {
			fvp_locked = true;
			break;
		}

		if (tvp_locked) {
			VOP_UNLOCK(tvp);
			tvp_locked = false;
		}
		if (fdvp != tdvp)
			VOP_UNLOCK(fdvp);
		VOP_UNLOCK(tdvp);
		/*
		 * Sleep without holding any conflicting locks until the
		 * contested vnode becomes free, then re-lock the directory
		 * pair before retrying.
		 */
		vn_lock(fvp, LK_EXCLUSIVE | LK_RETRY);
		VOP_UNLOCK(fvp);
		vn_lock_pair(fdvp, false, LK_EXCLUSIVE, tdvp, false,
		    LK_EXCLUSIVE);
		if (fdvp != tdvp)
			fdvp_locked = true;
	}

	fdp = VTONODE(fdvp);
	fnp = VTONODE(fvp);
	tdp = VTONODE(tdvp);
	tnp = tvp != NULL ? VTONODE(tvp) : NULL;

	/*
	 * Phase 2: Tree topology, doomed state, and directory sanity
	 * validation.
	 *
	 * Verify none of the vnodes were doomed or unlinked, verify parent
	 * directory locators have not shifted, perform ancestor cycle check
	 * via exfat_checkpath() when renaming directories, and ensure target
	 * directory is empty if overwriting.
	 */
	if (VN_IS_DOOMED(fdvp) || VN_IS_DOOMED(fvp) || VN_IS_DOOMED(tdvp) ||
	    (tvp != NULL && VN_IS_DOOMED(tvp)) ||
	    fdp == NULL || fnp == NULL || tdp == NULL ||
	    (tvp != NULL && tnp == NULL) ||
	    (fdp->node_flag & EXFAT_NODE_UNLINKED) != 0 ||
	    (fnp->node_flag & EXFAT_NODE_UNLINKED) != 0 ||
	    (tdp->node_flag & EXFAT_NODE_UNLINKED) != 0 ||
	    (tnp != NULL && (tnp->node_flag & EXFAT_NODE_UNLINKED) != 0)) {
		error = ENOENT;
		goto out;
	}

	if (fnp->node_parent_dirclust != fdp->node_dirclust ||
	    fnp->node_parent_diroffset != fdp->node_diroffset) {
		error = ERELOOKUP;
		goto out;
	}
	if (tnp != NULL && (tnp->node_parent_dirclust != tdp->node_dirclust ||
	    tnp->node_parent_diroffset != tdp->node_diroffset)) {
		error = ERELOOKUP;
		goto out;
	}

	if (fvp->v_type == VDIR) {
		error = exfat_checkpath(fnp, tdp, fdp);
		if (error != 0)
			goto out;

		if (tvp != NULL) {
			if (tvp->v_type != VDIR) {
				error = ENOTDIR;
				goto out;
			}
			error = exfat_dir_is_empty(VTONODE(tvp));
			if (error != 0)
				goto out;
		}
	} else if (tvp != NULL && tvp->v_type == VDIR) {
		error = EISDIR;
		goto out;
	}

	/*
	 * Phase 3: Target name conversion, validation, and overwrite prep.
	 *
	 * Convert target name to UTF-16 and validate characters per Spec
	 * Section 7.7.3. If overwriting tvp, read its directory entry set
	 * for rollback and delete it to free its slots for reuse.
	 */
	error = exfat_utf8_to_utf16(tcnp->cn_nameptr, tcnp->cn_namelen,
	    name_utf16, EXFAT_MAX_NAME_CHARS, &name_nchars);
	if (error != 0)
		goto out;

	if (!exfat_is_valid_name(name_utf16, name_nchars)) {
		error = EINVAL;
		goto out;
	}

	if (tvp != NULL) {
		error = exfat_dentry_read_set(pmp, tdp, tnp->node_dirclust,
		    tnp->node_diroffset, saved_tdset, &saved_tcount);
		if (error != 0)
			goto out;
		error = exfat_dentry_delete_set(pmp, tdp, tnp->node_dirclust,
		    tnp->node_diroffset, saved_tcount);
		if (error != 0)
			goto out;
		tdp->node_dir_hint_clust = tnp->node_dirclust;
		tdp->node_dir_hint_offset = tnp->node_diroffset;
	}

	name_hash = exfat_name_hash(pmp, name_utf16, name_nchars);

	/*
	 * Form the new directory entry set (Primary File Entry + Stream
	 * Extension Entry + File Name Entries).
	 *
	 * Note: Per Microsoft exFAT Spec 6.4.1.2.2 and 7.8/7.9, any optional
	 * benign secondary directory entries (such as Vendor Extension 0xE0 or
	 * Vendor Allocation 0xE1 entries) that may have followed the File Name
	 * entries in the old set are ignored and not preserved on rename.
	 * Benign secondary entries are defined by the specification as
	 * optional and safe to ignore for implementations that do not manage
	 * them.
	 */
	num_name_entries = howmany(name_nchars, EXFAT_CHARS_PER_NAME_ENTRY);
	total_entries = 2 + num_name_entries;

	/*
	 * Phase 4: Allocate directory entry set in target directory.
	 *
	 * Find a contiguous slot run of total_entries (Primary File Entry +
	 * Stream Extension Entry + File Name Entries) in tdp.
	 */
	error = exfat_dentry_find_free_slot(tdp, total_entries, &slot_cluster,
	    &slot_offset);
	if (error != 0) {
		if (tvp != NULL)
			(void)exfat_dentry_write_set(pmp, tdp,
			    tnp->node_dirclust, tnp->node_diroffset,
			    saved_tdset, saved_tcount);
		goto out;
	}

	dentries = malloc(total_entries * sizeof(union exfat_dentry),
	    M_TEMP, M_WAITOK | M_ZERO);

	/* Flush any pending timestamps before moving entry */
	exfat_times(fnp);

	/*
	 * Phase 5: Synthesize and write directory entry set.
	 *
	 * Build Primary File Entry (Spec Section 7.4), Stream Extension
	 * Entry (Spec Section 7.6), and File Name Entries (Spec Section 7.7),
	 * compute SetChecksum (Spec Section 7.4.3), and commit the set to
	 * disk via exfat_dentry_write_set().
	 */
	/* 1. Primary File Entry */
	dentries[0].file.fe_type = EXFAT_ENTRY_FILE;
	dentries[0].file.fe_secondary_count = 1 + num_name_entries;
	dentries[0].file.fe_file_attributes = htole16(fnp->node_attributes);
	dentries[0].file.fe_create_timestamp = htole32(fnp->node_ctime);
	dentries[0].file.fe_last_modified_timestamp = htole32(fnp->node_mtime);
	dentries[0].file.fe_last_access_timestamp = htole32(fnp->node_atime);
	dentries[0].file.fe_create_10ms_increment = fnp->node_c_10ms;
	dentries[0].file.fe_last_modified_10ms_increment = fnp->node_m_10ms;
	dentries[0].file.fe_create_tz_offset = fnp->node_c_tz;
	dentries[0].file.fe_last_modified_tz_offset = fnp->node_m_tz;
	dentries[0].file.fe_last_access_tz_offset = fnp->node_a_tz;

	/* 2. Stream Extension Entry */
	fnp->node_stream_flags |= EXFAT_FLAG_ALLOC_POSSIBLE;
	if (!EXFAT_CLUSTER_VALID(pmp, fnp->node_first_cluster))
		fnp->node_stream_flags &= ~EXFAT_FLAG_NO_FAT_CHAIN;
	dentries[1].stream.se_type = EXFAT_ENTRY_STREAM;
	dentries[1].stream.se_general_flags = fnp->node_stream_flags;
	dentries[1].stream.se_name_length = name_nchars;
	dentries[1].stream.se_name_hash = htole16(name_hash);
	dentries[1].stream.se_first_cluster = htole32(fnp->node_first_cluster);
	dentries[1].stream.se_data_length = htole64(fnp->node_size);
	/*
	 * Per Spec §7.6.5, ValidDataLength shall equal DataLength for a
	 * directory. When synthesizing the Stream Extension entry for a
	 * renamed object, clamp valid_len to node_size for directories (and
	 * defensively if node_valid_size exceeds node_size). This guarantees
	 * that the on-disk entry strictly conforms to §7.6.5 without leaking
	 * non-conforming in-memory state, and the dentry set checksum is
	 * recalculated over these finalized fields immediately below.
	 */
	if ((fnp->node_attributes & EXFAT_ATTR_DIRECTORY) != 0 ||
	    fnp->node_valid_size > fnp->node_size)
		valid_len = fnp->node_size;
	else
		valid_len = fnp->node_valid_size;
	dentries[1].stream.se_valid_data_length = htole64(valid_len);

	/* 3. File Name Entries */
	for (uint8_t n = 0; n < num_name_entries; n++) {
		struct exfat_dentry_name *ne = &dentries[2 + n].name;
		ne->ne_type = EXFAT_ENTRY_NAME;
		for (size_t c = 0; c < EXFAT_CHARS_PER_NAME_ENTRY; c++) {
			size_t src_idx = n * EXFAT_CHARS_PER_NAME_ENTRY + c;
			if (src_idx < name_nchars)
				ne->ne_file_name[c] =
				    htole16(name_utf16[src_idx]);
			else
				ne->ne_file_name[c] = 0;
		}
	}

	/* Checksum */
	exfat_dentry_set_checksum(dentries, total_entries);

	/* Write new directory entry set */
	error = exfat_dentry_write_set(pmp, tdp, slot_cluster, slot_offset,
	    dentries, total_entries);
	free(dentries, M_TEMP);
	if (error != 0) {
		tdp->node_dir_hint_clust = slot_cluster;
		tdp->node_dir_hint_offset = slot_offset;
		if (tvp != NULL)
			(void)exfat_dentry_write_set(pmp, tdp,
			    tnp->node_dirclust, tnp->node_diroffset,
			    saved_tdset, saved_tcount);
		(void)exfat_dir_shrink(tdp);
		goto out;
	}

	/*
	 * Phase 6: Delete old directory entry set and update node locators.
	 *
	 * Delete the old entry set in fdp, unlink tvp if overwritten, update
	 * fnp directory coordinates (dirclust, diroffset, parent pointers),
	 * update child directory parent pointers if fvp is a directory,
	 * update directory timestamps, and shrink trailing empty directory
	 * clusters.
	 */
	error = exfat_dentry_delete_set(pmp, fdp, fnp->node_dirclust,
	    fnp->node_diroffset, 1 + fnp->node_secondary_count);
	if (error != 0) {
		(void)exfat_dentry_delete_set(pmp, tdp, slot_cluster,
		    slot_offset, total_entries);
		tdp->node_dir_hint_clust = slot_cluster;
		tdp->node_dir_hint_offset = slot_offset;
		if (tvp != NULL)
			(void)exfat_dentry_write_set(pmp, tdp,
			    tnp->node_dirclust, tnp->node_diroffset,
			    saved_tdset, saved_tcount);
		(void)exfat_dir_shrink(tdp);
		goto out;
	}
	if (tvp != NULL) {
		tnp->node_flag |= EXFAT_NODE_UNLINKED;
		cache_purge(tvp);
	}
	fdp->node_dir_hint_clust = fnp->node_dirclust;
	fdp->node_dir_hint_offset = fnp->node_diroffset;
	fdp->node_flag |= EXFAT_NODE_MTIME | EXFAT_NODE_DIRTY;
	tdp->node_flag |= EXFAT_NODE_MTIME | EXFAT_NODE_DIRTY;
	/* Best-effort shrinkage of trailing empty directory clusters. */
	(void)exfat_dir_shrink(fdp);
	if (fdp != tdp && tvp != NULL)
		(void)exfat_dir_shrink(tdp);

	/* Update node location */
	old_dirclust = fnp->node_dirclust;
	old_diroffset = fnp->node_diroffset;
	fnp->node_dirclust = slot_cluster;
	fnp->node_diroffset = slot_offset;
	fnp->node_inode = exfat_make_inode(slot_cluster, slot_offset);
	fnp->node_parent_dirclust = tdp->node_dirclust;
	fnp->node_parent_diroffset = tdp->node_diroffset;
	fnp->node_secondary_count = 1 + num_name_entries;
	fnp->node_flag &= ~(EXFAT_NODE_MTIME | EXFAT_NODE_DIRTY |
	    EXFAT_NODE_ATIME);

	if (fvp->v_type == VDIR) {
		struct vnode *cvp, *mvp;

		MNT_VNODE_FOREACH_ALL(cvp, fvp->v_mount, mvp) {
			struct exfat_node *cnp;

			if (cvp->v_type == VNON) {
				VI_UNLOCK(cvp);
				continue;
			}
			cnp = VTONODE(cvp);
			if (cnp != NULL &&
			    cnp->node_parent_dirclust == old_dirclust &&
			    cnp->node_parent_diroffset == old_diroffset) {
				cnp->node_parent_dirclust = slot_cluster;
				cnp->node_parent_diroffset = slot_offset;
			}
			VI_UNLOCK(cvp);
		}
	}

	vfs_hash_rehash(fvp, exfat_vnode_hash(fnp->node_inode));

	cache_purge(fvp);
	cache_purge_negative(tdvp);

out:
	if (fvp_locked)
		VOP_UNLOCK(fvp);
	if (fdvp_locked && fdvp != tdvp)
		VOP_UNLOCK(fdvp);
	if (tdvp == tvp)
		vrele(tdvp);
	else
		vput(tdvp);
	if (tvp != NULL) {
		if (tvp_locked)
			vput(tvp);
		else
			vrele(tvp);
	}
	vrele(fdvp);
	vrele(fvp);
	return (error);
}

static int
exfat_inactive(struct vop_inactive_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);
	struct exfat_mount *pmp;

	if (np == NULL)
		return (0);

	pmp = np->node_pmp;

	if ((np->node_flag & EXFAT_NODE_UNLINKED) != 0) {
		if (pmp != NULL && (pmp->pm_flags & EXFAT_MNT_RONLY) == 0) {
			if (np->node_size > 0)
				exfat_truncate(np, 0);
			else if (EXFAT_CLUSTER_VALID(pmp,
			    np->node_first_cluster)) {
				exfat_free_cluster_chain(pmp,
				    np->node_first_cluster,
				    (np->node_stream_flags &
				    EXFAT_FLAG_NO_FAT_CHAIN) != 0,
				    pmp->pm_cluster_size);
				np->node_first_cluster = 0;
			}
			vtruncbuf(vp, 0, pmp->pm_cluster_size);
		}
		np->node_attributes = 0;
		vrecycle(vp);
		return (0);
	}

	if ((np->node_flag & (EXFAT_NODE_MTIME | EXFAT_NODE_ATIME |
	    EXFAT_NODE_DIRTY)) != 0 &&
	    pmp != NULL && (pmp->pm_flags & EXFAT_MNT_RONLY) == 0)
		exfat_node_sync(np);

	return (0);
}

static int
exfat_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct exfat_node *np = VTONODE(vp);

	if (np == NULL)
		return (0);

	vfs_hash_remove(vp);
	VI_LOCK(vp);
	vp->v_data = NULL;
	VI_UNLOCK(vp);

	/*
	 * Drain in-flight lockless lookup readers (cache_fplookup) before
	 * freeing the exfat_node.  During fast-path lookup, directory vnodes
	 * are traversed unreferenced under an SMR read section (vfs_smr_enter).
	 * Setting vp->v_data = NULL ensures subsequent readers reject the
	 * vnode with EAGAIN via VTONODE_SMR(), while vfs_smr_synchronize()
	 * guarantees that any reader that observed np has exited its SMR
	 * critical section before exfat_node_free() releases the memory.
	 */
	vfs_smr_synchronize();
	exfat_node_free(np);
	return (0);
}

/* Global vfs data structures for exfat */
struct vop_vector exfat_vnodeops = {
	.vop_default =		&default_vnodeops,

	.vop_access =		exfat_access,
	.vop_advlock =		vop_stdadvlock,
	.vop_advlockasync =	vop_stdadvlockasync,
	.vop_advlockpurge =	vop_stdadvlockpurge,
	.vop_allocate =		exfat_allocate,
	.vop_bmap =		exfat_bmap,
	.vop_cachedlookup =	exfat_lookup,
	.vop_close =		exfat_close,
	.vop_create =		exfat_create,
	.vop_deleteextattr =	exfat_deleteextattr,
	.vop_fdatasync =	vop_stdfdatasync_buf,
	.vop_fplookup_symlink =	VOP_EAGAIN,
	.vop_fplookup_vexec =	exfat_fplookup_vexec,
	.vop_fsync =		exfat_fsync,
	.vop_getattr =		exfat_getattr,
	.vop_getextattr =	exfat_getextattr,
	.vop_getpages =		exfat_getpages,
	.vop_inactive =		exfat_inactive,
	.vop_ioctl =		exfat_ioctl,
	.vop_link =		exfat_link,
	.vop_listextattr =	exfat_listextattr,
	.vop_lookup =		vfs_cache_lookup,
	.vop_mkdir =		exfat_mkdir,
	.vop_mknod =		exfat_mknod,
	.vop_open =		exfat_open,
	.vop_pathconf =		exfat_pathconf,
	.vop_print =		exfat_print,
	.vop_read =		exfat_read,
	.vop_readdir =		exfat_readdir,
	.vop_reclaim =		exfat_reclaim,
	.vop_remove =		exfat_remove,
	.vop_rename =		exfat_rename,
	.vop_rmdir =		exfat_rmdir,
	.vop_setattr =		exfat_setattr,
	.vop_setextattr =	exfat_setextattr,
	.vop_stat =		exfat_stat,
	.vop_strategy =		exfat_strategy,
	.vop_symlink =		exfat_symlink,
#if __FreeBSD_version >= 1600019
	.vop_update_atime =	exfat_update_atime,
#else
	.vop_mmapped =		exfat_mmapped,
#endif
	.vop_vptofh =		exfat_vptofh,
	.vop_write =		exfat_write,
};
VFS_VOP_VECTOR_REGISTER(exfat_vnodeops);
