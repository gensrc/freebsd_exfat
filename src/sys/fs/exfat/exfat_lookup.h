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

#ifndef _FS_EXFAT_EXFAT_LOOKUP_H_
#define _FS_EXFAT_EXFAT_LOOKUP_H_

#include <sys/param.h>
#include <sys/vnode.h>

#include <fs/exfat/exfat_ondisk.h>

#ifdef _KERNEL

struct buf;
struct componentname;
struct exfat_mount;
struct exfat_node;
struct vattr;

/*
 * Directory cursor for traversing directory entries across cluster boundaries.
 * Holds buffer cache references and tracks progress through directory chains.
 */
struct exfat_dir_cursor {
	struct exfat_mount	*dc_pmp;	/* Mount structure */
	struct exfat_node	*dc_dp;		/* Directory node */
	uint32_t		dc_cluster;	/* Current cluster number */
	uint32_t		dc_offset;	/* Byte offset within cluster */
	struct buf		*dc_bp;		/* Cached cluster buffer */
	uint32_t		dc_clusters_read; /* Clusters read so far */
};

/*
 * Maximum directory entries in a set:
 * 1 primary File Directory Entry + 1 Stream Extension + up to 17 File Name.
 */
#define EXFAT_MAX_ENTRY_SET	19

void	exfat_dir_cursor_init(struct exfat_mount *pmp, struct exfat_node *dp,
	    struct exfat_dir_cursor *dc);
int	exfat_dir_cursor_get(struct exfat_dir_cursor *dc,
	    const union exfat_dentry **dentp, uint32_t *entry_cluster,
	    uint32_t *entry_offset);
void	exfat_dir_cursor_put(struct exfat_dir_cursor *dc);
int	exfat_dir_cursor_next(struct exfat_dir_cursor *dc);
int	exfat_dir_cursor_skip(struct exfat_dir_cursor *dc, uint32_t count);
int	exfat_dir_cursor_seek(struct exfat_mount *pmp, struct exfat_node *dp,
	    struct exfat_dir_cursor *dc, uint32_t target_disk_offset);

int	exfat_dentry_read_set(struct exfat_mount *pmp, struct exfat_node *dp,
	    uint32_t dirclust, uint32_t diroffset,
	    union exfat_dentry *dentries, uint8_t *countp);
int	exfat_dentry_write_set(struct exfat_mount *pmp, struct exfat_node *dp,
	    uint32_t dirclust, uint32_t diroffset,
	    const union exfat_dentry *dentries, uint8_t count);
int	exfat_dentry_delete_set(struct exfat_mount *pmp, struct exfat_node *dp,
	    uint32_t dirclust, uint32_t diroffset, uint8_t count);
int	exfat_dentry_find_free_slot(struct exfat_node *dp, uint8_t count,
	    uint32_t *slot_clusterp, uint32_t *slot_offsetp);
int	exfat_dir_is_empty(struct exfat_node *dp);
int	exfat_dir_shrink(struct exfat_node *dp);

#endif /* _KERNEL */

#endif /* _FS_EXFAT_EXFAT_LOOKUP_H_ */
