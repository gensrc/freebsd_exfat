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

#ifndef _FS_EXFAT_EXFAT_FAT_H_
#define _FS_EXFAT_EXFAT_FAT_H_

#include <sys/param.h>
#include <sys/buf.h>

#include <fs/exfat/exfat_ondisk.h>

#ifdef _KERNEL

struct exfat_mount;

/*
 * Cluster validation macro.
 * Verifies that cn is within cluster heap bounds [2, cluster_count + 2).
 */
#define EXFAT_CLUSTER_VALID(pmp, cn) \
	exfat_cluster_is_valid((cn), (pmp)->pm_cluster_count)

/*
 * Cluster address translation and I/O
 */
daddr_t	exfat_cntodaddr(struct exfat_mount *pmp, uint32_t cn);
int	exfat_read_cluster(struct exfat_mount *pmp, uint32_t cn,
	    struct buf **bpp);
int	exfat_read_cluster_ra(struct exfat_mount *pmp, uint32_t cn,
	    uint32_t next_cn, struct buf **bpp);

/*
 * FAT chain traversal cursor.
 * Caches the active FAT sector buffer across multi-cluster lookups.
 */
struct exfat_fat_cursor {
	struct exfat_mount	*fc_pmp;
	struct buf		*fc_bp;
	uint64_t		fc_cur_sector;
	uint64_t		fc_fat_offset;
};

/*
 * FAT chain traversal and updates
 */
void	exfat_fat_cursor_init(struct exfat_mount *pmp,
	    struct exfat_fat_cursor *fc);
int	exfat_fat_cursor_get(struct exfat_fat_cursor *fc, uint32_t cn,
	    uint32_t *next_cn);
void	exfat_fat_cursor_put(struct exfat_fat_cursor *fc);
int	exfat_fat_get(struct exfat_mount *pmp, uint32_t cn, uint32_t *next_cn);
int	exfat_fat_set(struct exfat_mount *pmp, uint32_t cn, uint32_t next_cn);
int	exfat_fat_clear_range(struct exfat_mount *pmp, uint32_t start_cn,
	    uint32_t count);
int	exfat_fat_link_range(struct exfat_mount *pmp, uint32_t start_cn,
	    uint32_t count, uint32_t tail_val);
int	exfat_fat_contig_forward(struct exfat_mount *pmp, uint32_t start_cn,
	    uint32_t maxrun, int *runp);
int	exfat_fat_contig_backward(struct exfat_mount *pmp, uint32_t start_cn,
	    uint32_t maxrun, int *runb);
int	exfat_free_cluster_chain(struct exfat_mount *pmp, uint32_t start_cn,
	    bool no_fat_chain, uint64_t size);
bool	exfat_cluster_in_chain(struct exfat_mount *pmp, uint32_t start_cn,
	    uint8_t stream_flags, uint64_t size, uint32_t target_cn);

/*
 * Allocation Bitmap synchronization and cluster allocation
 */
bool	exfat_bitmap_is_cluster_allocated(struct exfat_mount *pmp,
	    uint32_t cn);
int	exfat_bitmap_alloc_contiguous_at(struct exfat_mount *pmp,
	    uint32_t start_cn, uint32_t count);
int	exfat_bitmap_alloc_clusters(struct exfat_mount *pmp, uint32_t count,
	    uint32_t *start_cnp, bool *contigp);
int	exfat_bitmap_free_clusters(struct exfat_mount *pmp, uint32_t start_cn,
	    uint32_t count);

#endif /* _KERNEL */

#endif /* _FS_EXFAT_EXFAT_FAT_H_ */
