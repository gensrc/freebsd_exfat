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

#ifndef _FSCK_EXFAT_H_
#define _FSCK_EXFAT_H_

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include <fs/exfat/exfat_ondisk.h>

/*
 * Command line options
 */
extern int alwaysno;	/* assume "no" for all questions (-n) */
extern int alwaysyes;	/* assume "yes" for all questions (-y) */
extern int preen;	/* preen mode (-p) */
extern int rdonly;	/* opened read-only */
extern int verbose;	/* verbose output (-v) */
extern int force;	/* force check even if clean (-f) */

/*
 * Return code bitmasks
 */
#define FSOK		0
#define FSBOOTMOD	1	/* Boot block was modified */
#define FSDIRMOD	2	/* Directory structure was modified */
#define FSFATMOD	4	/* FAT / Bitmap was modified */
#define FSERROR		8	/* Unrecovered error remains */
#define FSFATAL		16	/* Unrecoverable error occurred */
#define FSDIRTY		32	/* Filesystem remains dirty */

/*
 * Exit status codes (per fsck(8) conventions).
 *
 * Historically in BSD Unix, fsck exit codes were designed as powers-of-two
 * bitmasks so that the parallel preen coordinator (sbin/fsck/preen.c) can
 * accumulate status across multiple concurrent checks via:
 *     sumstatus |= retcode;
 *
 * Compatibility across FreeBSD checkers and /etc/rc.d/fsck:
 * - FSCK_EXIT_OK (0): Universal across all checkers; clean file system.
 * - FSCK_EXIT_MODIFIED (1): Inconsistencies corrected (boot continues).
 * - FSCK_EXIT_USAGE (1): Command line usage error.
 * - FSCK_EXIT_REBOOT (2): System reboot recommended (e.g. SIGQUIT in FFS).
 * - FSCK_EXIT_UNCORRECTED (4): Standard Unix/LSB convention for uncorrected
 *   inconsistencies. Note that in native FreeBSD fsck_ffs and /etc/rc.d/fsck,
 *   code 4 historically signals that a mounted root filesystem was modified
 *   and triggers a reboot, whereas fsck_msdosfs exits with 8 on uncorrected
 *   errors to invoke stop_boot (single-user shell).
 * - FSCK_EXIT_NO_BG (5): Returned on -F to signal that background checking
 *   is not supported and foreground check is required (matches fsck_msdosfs).
 * - FSCK_EXIT_ERROR (8): Operational or fatal error exit across all checkers;
 *   causes /etc/rc.d/fsck to prompt for fsck -y or drop to single-user shell.
 */
#define FSCK_EXIT_OK		0	/* File system is clean */
#define FSCK_EXIT_MODIFIED	1	/* File system was modified/corrected */
#define FSCK_EXIT_USAGE		1	/* Usage error */
#define FSCK_EXIT_REBOOT	2	/* Reboot recommended */
#define FSCK_EXIT_UNCORRECTED	4	/* Inconsistencies not corrected */
#define FSCK_EXIT_NO_BG		5	/* Background check not supported */
#define FSCK_EXIT_ERROR		8	/* Operational error */

/*
 * Cluster validation macro.
 * Verifies that cn is within cluster heap bounds [2, cluster_count + 2).
 */
#define EXFAT_CLUSTER_VALID(chk, cn) \
	exfat_cluster_is_valid((cn), (chk)->boot.cluster_count)

/*
 * Cached boot parameters extracted during boot region verification.
 */
struct exfat_boot {
	uint64_t	volume_length;		/* volume size in sectors */
	uint32_t	sector_size;
	uint32_t	cluster_size;
	uint8_t		sector_shift;
	uint8_t		cluster_shift;
	uint32_t	fat_offset;		/* sector offset of FAT */
	uint32_t	fat_length;		/* length of FAT in sectors */
	uint32_t	cluster_heap_offset;	/* sector offset of cluster 2 */
	uint32_t	cluster_count;		/* total clusters in heap */
	uint32_t	root_dir_cluster;
	uint32_t	volume_serial;
	uint16_t	fs_revision;
	uint16_t	volume_flags;
	uint8_t		number_of_fats;
	uint8_t		percent_in_use;
};

/*
 * Main consistency checking context across all inspection phases.
 */
struct exfat_chk {
	int			fd;
	struct exfat_boot	boot;
	uint8_t			*disk_bitmap;
	uint64_t		bitmap_len;
	uint32_t		bitmap_cluster;
	uint64_t		bitmap2_len;
	uint32_t		bitmap2_cluster;
	uint8_t			*used_bitmap;	/* Track referenced clusters */
	uint8_t			*dup_bitmap;	/* Track duplicate clusters */
	uint16_t		*upcase_table;	/* 64K entries = 128 KiB */
	uint32_t		upcase_cluster;
	uint64_t		upcase_len;
	uint32_t		upcase_checksum;
#define EXFAT_MAX_LABEL_CHARS	EXFAT_MAX_VOLUME_LABEL_CHARS

	char			vol_label[EXFAT_MAX_LABEL_CHARS * 4 + 1];
	uint64_t		num_files;
	uint64_t		num_dirs;
	uint64_t		clusters_free;
	uint64_t		clusters_bad;
	uint8_t			*fat_cache;
	off_t			fat_cache_off;
	size_t			fat_cache_valid;
	uint32_t		lostdir_cluster;
	uint32_t		lostdir_dentry_cn;
	size_t			lostdir_dentry_idx;
	uint64_t		lostdir_size;
	bool			lostdir_found;
	bool			lostdir_no_fat_chain;
};

int ask(int def, const char *fmt, ...) __printflike(2, 3);
int checkfilesys(const char *fname);

/* boot.c */
int check_boot(struct exfat_chk *chk);
int write_boot_clean(struct exfat_chk *chk);

/* fat.c */
off_t cluster_to_offset(const struct exfat_chk *chk, uint32_t cn);
int read_cluster(const struct exfat_chk *chk, uint32_t cn, void *buf);
int write_cluster(const struct exfat_chk *chk, uint32_t cn, const void *buf);
int fat_get(struct exfat_chk *chk, uint32_t cn, uint32_t *next_cn);
int fat_set(struct exfat_chk *chk, uint32_t cn, uint32_t next_cn);
int check_fat_mirror(struct exfat_chk *chk);
int mark_cluster_used(struct exfat_chk *chk, uint32_t cn, const char *owner);
bool is_cluster_used(const struct exfat_chk *chk, uint32_t cn);
int check_clusters(struct exfat_chk *chk);

/* dir.c */
int scan_root_metadata(struct exfat_chk *chk);
int check_dirtree(struct exfat_chk *chk);
int reconnect_orphans(struct exfat_chk *chk);
int get_vol_label(struct exfat_chk *chk, char *dst, size_t dstlen);
int set_vol_label(struct exfat_chk *chk, const char *label);

#endif /* _FSCK_EXFAT_H_ */
