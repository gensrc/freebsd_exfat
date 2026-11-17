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

#ifndef _NEWFS_EXFAT_H_
#define _NEWFS_EXFAT_H_

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include <fs/exfat/exfat_ondisk.h>

#define EXFAT_MAX_LABEL_CHARS	EXFAT_MAX_VOLUME_LABEL_CHARS

/*
 * Command-line configuration options for filesystem formatting.
 */
struct exfat_mkfs_opts {
	const char	*special;	/* Target device or image path */
	const char	*volume_label;	/* Volume label string */
	off_t		create_size;	/* -C: create image file size */
	off_t		volume_size;	/* -s: volume size */
	uint64_t	partition_offset; /* -p: partition offset in sectors */
	uint32_t	bytes_per_sector; /* -S: sector size in bytes */
	uint32_t	cluster_size;	/* -c: cluster size in bytes */
	uint32_t	volume_serial;	/* -I: 32-bit volume serial number */
	bool		no_create;	/* -N: dry run flag */
	bool		verbose;	/* -v: verbose reporting flag */
	bool		serial_set;	/* Explicit serial number provided */
};

extern const uint8_t exfat_default_upcase[];
extern const size_t exfat_default_upcase_len;
extern const uint32_t exfat_default_upcase_checksum;

int mkfs_exfat(const struct exfat_mkfs_opts *opts);

#endif /* _NEWFS_EXFAT_H_ */
