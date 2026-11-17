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

#ifndef _FS_EXFAT_EXFAT_VFSOPS_H_
#define _FS_EXFAT_EXFAT_VFSOPS_H_

#include <sys/param.h>
#include <sys/mount.h>

#include <fs/exfat/exfat_ioctl.h>
#include <fs/exfat/exfat_ondisk.h>

#ifdef _KERNEL
#include <sys/lock.h>
#include <sys/lockmgr.h>
#include <sys/malloc.h>

struct g_consumer;
struct bufobj;
struct cdev;
struct vnode;

MALLOC_DECLARE(M_EXFATMNT);
#endif

/*
 * Mount arguments structure for exFAT.
 *
 * Passed from userland mount_exfat(8) via the VFS mount system call
 * to configure device path, credentials, default permissions, and flags.
 */
struct exfat_args {
	char			*fspec;		/* Block special device path */
	struct oexport_args	export;		/* Network export information */
	uid_t			uid;		/* Owner UID */
	gid_t			gid;		/* Owner GID */
	mode_t			mask;		/* File permission mask */
	mode_t			dirmask;	/* Directory permission mask */
	int			flags;		/* Mount flags */
};

/*
 * exFAT Mount Flags
 */
#define EXFAT_MNT_RONLY	0x00000001	/* Mounted read-only */
#define EXFAT_MNT_TRIM	0x00000004	/* Issue BIO_DELETE (TRIM) on free */

#ifdef _KERNEL

/*
 * In-memory mount structure for exFAT filesystem (equivalent to
 * struct msdosfsmount in msdosfs).
 *
 * Anchors volume geometry, active GEOM consumer/vnode references, cached
 * VBR parameters, in-memory Allocation Bitmap, loaded Up-case table, and
 * volume locking primitives.
 *
 * Locking protocol:
 * - pm_lock protects filesystem-wide state: FAT sector updates, allocation
 *   bitmap modifications, free cluster counters, and directory hint rotors.
 *   Callers use EXFAT_LOCK() and EXFAT_UNLOCK().
 */
struct exfat_mount {
	struct mount		*pm_mountp;		/* VFS mount struct */
	struct g_consumer	*pm_cp;			/* GEOM consumer */
	struct bufobj		*pm_bo;			/* Buffer cache object */
	struct cdev		*pm_dev;		/* Character device */
	struct vnode		*pm_devvp;		/* Device vnode */

	/* Ownership and permission masks */
	uid_t			pm_uid;			/* Owner UID */
	gid_t			pm_gid;			/* Owner GID */
	mode_t			pm_mask;		/* File permission mask */
	mode_t			pm_dirmask;		/* Directory permission mask */
	uint64_t		pm_flags;		/* Mount flags (EXFAT_MNT_*) */

	/* Cached on-disk Volume Boot Record */
	struct exfat_boot_sector pm_vbr;

	/* Geometry and cluster offsets */
	uint64_t		pm_volume_length;	/* Volume size in sectors */
	uint32_t		pm_fat_offset;		/* First FAT sector offset */
	uint32_t		pm_fat_length;		/* FAT size in sectors */
	uint32_t		pm_cluster_heap_offset;	/* Sector offset of Cluster 2 */
	uint32_t		pm_cluster_count;	/* Total clusters in cluster heap */
	uint32_t		pm_rootdir_cluster;	/* First cluster of root directory */

	/* Shifts, masks, and byte sizes */
	uint8_t			pm_sector_shift;	/* Sector size power of 2 */
	uint8_t			pm_cluster_shift;	/* Sectors per cluster power of 2 */
	uint32_t		pm_sector_size;		/* Sector size in bytes */
	uint32_t		pm_cluster_size;	/* Cluster size in bytes */
	uint32_t		pm_cluster_mask;	/* Cluster relative offset mask */

	/* Metadata files (Allocation Bitmap & Up-case table) */
	uint32_t		pm_bitmap_cluster;	/* First cluster of bitmap */
	uint64_t		pm_bitmap_length;	/* Bitmap size in bytes */
	uint8_t			*pm_bitmap;		/* In-memory allocation bitmap */
	uint32_t		pm_free_clusters;	/* Total free clusters in heap */
	uint32_t		pm_last_allocated_cluster; /* Next-fit rotor cursor */

	uint32_t		pm_upcase_cluster;	/* First cluster of up-case table */
	uint64_t		pm_upcase_length;	/* Up-case table size in bytes */
	uint32_t		pm_upcase_checksum;	/* Up-case table checksum */
	uint16_t		*pm_upcase;		/* In-memory up-case table */

	char			pm_vollabel[EXFAT_MAX_LABEL_LEN];

	struct lock		pm_lock;		/* Lock protecting filesystem state */
};

#define VFSTOEXFAT(mp)		((struct exfat_mount *)((mp)->mnt_data))
#define EXFAT_LOCK(pmp)		lockmgr(&(pmp)->pm_lock, LK_EXCLUSIVE, NULL)
#define EXFAT_UNLOCK(pmp)	lockmgr(&(pmp)->pm_lock, LK_RELEASE, NULL)
#define EXFAT_LOCK_ASSERT(pmp)	lockmgr_assert(&(pmp)->pm_lock, KA_XLOCKED)

/*
 * Public VFS operation table
 */
extern struct vfsops exfat_vfsops;

#endif /* _KERNEL */

#endif /* _FS_EXFAT_EXFAT_VFSOPS_H_ */
