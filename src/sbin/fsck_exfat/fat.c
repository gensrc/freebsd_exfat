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
#include <sys/endian.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fsck_exfat.h"
#include "fsutil.h"

/*
 * Convert cluster number cn to disk byte offset.
 *
 * Returns disk byte offset, or -1 if cn is invalid.
 */
off_t
cluster_to_offset(const struct exfat_chk *chk, uint32_t cn)
{
	if (!EXFAT_CLUSTER_VALID(chk, cn))
		return (-1);

	return ((off_t)exfat_cluster_to_sector(chk->boot.cluster_heap_offset,
	    chk->boot.cluster_shift, cn) * chk->boot.sector_size);
}

/*
 * Read an entire cluster from disk into user-supplied buffer buf.
 *
 * Returns 0 on success, EINVAL on invalid cluster, or EIO on read failure.
 */
int
read_cluster(const struct exfat_chk *chk, uint32_t cn, void *buf)
{
	off_t off = cluster_to_offset(chk, cn);
	ssize_t n;

	if (off < 0)
		return (EINVAL);

	n = pread(chk->fd, buf, chk->boot.cluster_size, off);
	if (n != (ssize_t)chk->boot.cluster_size) {
		pwarn("Cannot read cluster %u at offset %jd: %s\n",
		    cn, (intmax_t)off, strerror(errno));
		return (EIO);
	}
	return (0);
}

/*
 * Write an entire cluster from buffer buf to disk.
 *
 * Returns 0 on success, EROFS if read-only, or EIO on write failure.
 */
int
write_cluster(const struct exfat_chk *chk, uint32_t cn, const void *buf)
{
	off_t off = cluster_to_offset(chk, cn);
	ssize_t n;

	if (off < 0)
		return (EINVAL);

	if (rdonly)
		return (EROFS);

	n = pwrite(chk->fd, buf, chk->boot.cluster_size, off);
	if (n != (ssize_t)chk->boot.cluster_size) {
		pwarn("Cannot write cluster %u at offset %jd: %s\n",
		    cn, (intmax_t)off, strerror(errno));
		return (EIO);
	}
	return (0);
}

/*
 * Read the next cluster link for cluster cn from the active FAT.
 *
 * Uses an in-memory 64 KiB sliding window cache to minimize repeated I/O.
 *
 * Stores next cluster in *next_cn.
 * Returns 0 on success, EINVAL on invalid cluster, or EIO on read failure.
 */
int
fat_get(struct exfat_chk *chk, uint32_t cn, uint32_t *next_cn)
{
	off_t fat_start, fat_end, fat_rel_off;
	off_t chunk_rel_off, chunk_disk_off;
	size_t chunk_size, to_read, in_cache_off;
	uint32_t entry;
	ssize_t n;

	if (!EXFAT_CLUSTER_VALID(chk, cn))
		return (EINVAL);

	fat_start = (off_t)chk->boot.fat_offset * chk->boot.sector_size;
	if (chk->boot.number_of_fats > 1 &&
	    (chk->boot.volume_flags & EXFAT_VOL_ACTIVE_FAT))
		fat_start += (off_t)chk->boot.fat_length *
		    chk->boot.sector_size;
	fat_end = fat_start +
	    ((off_t)chk->boot.fat_length * chk->boot.sector_size);
	fat_rel_off = (off_t)cn * sizeof(uint32_t);

	chunk_size = 64 * 1024;
	if (chunk_size < chk->boot.sector_size)
		chunk_size = chk->boot.sector_size;

	chunk_rel_off = fat_rel_off - (fat_rel_off % chunk_size);
	chunk_disk_off = fat_start + chunk_rel_off;
	in_cache_off = (size_t)(fat_rel_off - chunk_rel_off);

	if (chk->fat_cache != NULL &&
	    chk->fat_cache_off == chunk_disk_off &&
	    in_cache_off + sizeof(entry) <= chk->fat_cache_valid) {
		memcpy(&entry, chk->fat_cache + in_cache_off, sizeof(entry));
		*next_cn = le32toh(entry);
		return (0);
	}

	if (chk->fat_cache == NULL) {
		chk->fat_cache = malloc(chunk_size);
		if (chk->fat_cache == NULL) {
			perr("Out of memory allocating FAT cache");
			return (ENOMEM);
		}
		chk->fat_cache_off = -1;
		chk->fat_cache_valid = 0;
	}

	to_read = chunk_size;
	if (chunk_disk_off + (off_t)to_read > fat_end)
		to_read = (size_t)(fat_end - chunk_disk_off);

	to_read = rounddown(to_read, chk->boot.sector_size);
	if (to_read == 0)
		return (EINVAL);

	n = pread(chk->fd, chk->fat_cache, to_read, chunk_disk_off);
	if (n != (ssize_t)to_read) {
		pwarn("Cannot read FAT at offset %jd (len %zu): %s\n",
		    (intmax_t)chunk_disk_off, to_read, strerror(errno));
		chk->fat_cache_off = -1;
		chk->fat_cache_valid = 0;
		return (EIO);
	}

	chk->fat_cache_off = chunk_disk_off;
	chk->fat_cache_valid = to_read;

	if (in_cache_off + sizeof(entry) > chk->fat_cache_valid)
		return (EIO);

	memcpy(&entry, chk->fat_cache + in_cache_off, sizeof(entry));
	*next_cn = le32toh(entry);
	return (0);
}

/*
 * Update the cluster link for cluster cn in all FATs on disk.
 *
 * Invalidates the in-memory FAT sliding cache upon writing.
 *
 * Returns 0 on success, EROFS if read-only, or EIO on write failure.
 */
int
fat_set(struct exfat_chk *chk, uint32_t cn, uint32_t next_cn)
{
	off_t disk_off, fat_rel_off, fat_start, sec_off;
	uint8_t *sec_buf;
	size_t ent_off, sec_size;
	ssize_t n;
	uint32_t entry;
	unsigned int fat_idx;

	if (!EXFAT_CLUSTER_VALID(chk, cn))
		return (EINVAL);

	if (rdonly)
		return (EROFS);

	sec_size = chk->boot.sector_size;
	sec_buf = malloc(sec_size);
	if (sec_buf == NULL) {
		pwarn("Out of memory writing FAT entry\n");
		return (ENOMEM);
	}

	entry = htole32(next_cn);
	fat_rel_off = (off_t)cn * sizeof(uint32_t);

	for (fat_idx = 0; fat_idx < chk->boot.number_of_fats; fat_idx++) {
		fat_start = ((off_t)chk->boot.fat_offset +
		    (off_t)fat_idx * chk->boot.fat_length) *
		    chk->boot.sector_size;
		disk_off = fat_start + fat_rel_off;
		sec_off = rounddown(disk_off, sec_size);
		ent_off = (size_t)(disk_off % sec_size);

		n = pread(chk->fd, sec_buf, sec_size, sec_off);
		if (n != (ssize_t)sec_size) {
			pwarn("Cannot read FAT at offset %jd: %s\n",
			    (intmax_t)sec_off, strerror(errno));
			free(sec_buf);
			chk->fat_cache_off = -1;
			chk->fat_cache_valid = 0;
			return (EIO);
		}

		memcpy(sec_buf + ent_off, &entry, sizeof(entry));

		n = pwrite(chk->fd, sec_buf, sec_size, sec_off);
		if (n != (ssize_t)sec_size) {
			pwarn("Cannot write FAT at offset %jd: %s\n",
			    (intmax_t)sec_off, strerror(errno));
			free(sec_buf);
			chk->fat_cache_off = -1;
			chk->fat_cache_valid = 0;
			return (EIO);
		}
	}
	free(sec_buf);

	/* Invalidate FAT cache */
	chk->fat_cache_off = -1;
	chk->fat_cache_valid = 0;

	return (0);
}

/*
 * Compare and synchronize FAT1 and FAT2 on dual-FAT volumes.
 *
 * Determines the active FAT from VolumeFlags and overwrites the inactive FAT
 * if discrepancies are discovered and user approves.
 *
 * Returns FSOK, FSFATMOD, FSERROR, or FSFATAL.
 */
int
check_fat_mirror(struct exfat_chk *chk)
{
	off_t active_start, inactive_start, off;
	uint8_t *buf_act, *buf_inact;
	size_t chunk_size, remaining;
	uint64_t diff_sectors;
	int mod;
	bool active_is_fat1;

	if (chk->boot.number_of_fats < 2)
		return (FSOK);

	/*
	 * Phase 1: Active FAT orientation and buffer allocation.
	 *
	 * Determine the active FAT from VolumeFlags ActiveFat bit (Spec
	 * Section 3.1.13.1), compute byte offsets for active and inactive
	 * tables, and allocate stream comparison buffers.
	 */
	diff_sectors = 0;
	mod = FSOK;
	active_is_fat1 = (chk->boot.volume_flags & EXFAT_VOL_ACTIVE_FAT) != 0;
	if (active_is_fat1) {
		active_start = ((off_t)chk->boot.fat_offset +
		    chk->boot.fat_length) * chk->boot.sector_size;
		inactive_start = (off_t)chk->boot.fat_offset *
		    chk->boot.sector_size;
	} else {
		active_start = (off_t)chk->boot.fat_offset *
		    chk->boot.sector_size;
		inactive_start = ((off_t)chk->boot.fat_offset +
		    chk->boot.fat_length) * chk->boot.sector_size;
	}

	chunk_size = 64 * 1024;
	if (chunk_size < chk->boot.sector_size)
		chunk_size = chk->boot.sector_size;

	buf_act = malloc(chunk_size);
	buf_inact = malloc(chunk_size);
	if (buf_act == NULL || buf_inact == NULL) {
		free(buf_act);
		free(buf_inact);
		perr("Out of memory comparing FAT mirrors");
		return (FSFATAL);
	}

	remaining = (size_t)chk->boot.fat_length * chk->boot.sector_size;
	off = 0;

	/*
	 * Phase 2: Chunked streaming comparison of FAT mirrors.
	 *
	 * Read both FAT tables concurrently in chunks, detecting and
	 * tallying differing sectors.
	 */
	while (remaining > 0) {
		size_t to_read = MIN(remaining, chunk_size);
		ssize_t n1, n2;

		n1 = pread(chk->fd, buf_act, to_read, active_start + off);
		n2 = pread(chk->fd, buf_inact, to_read, inactive_start + off);
		if (n1 != (ssize_t)to_read || n2 != (ssize_t)to_read) {
			pwarn("Cannot read FAT sectors for comparison\n");
			free(buf_act);
			free(buf_inact);
			return (FSERROR);
		}

		if (memcmp(buf_act, buf_inact, to_read) != 0) {
			size_t s;

			for (s = 0; s < to_read; s += chk->boot.sector_size)
				if (memcmp(buf_act + s, buf_inact + s,
				    chk->boot.sector_size) != 0)
					diff_sectors++;
		}

		remaining -= to_read;
		off += to_read;
	}

	if (diff_sectors > 0) {
		pwarn("FAT mirror mismatch (%ju sector(s) differ)\n",
		    diff_sectors);
		/*
		 * Phase 3: Inactive FAT mirror synchronization.
		 *
		 * Overwrite the inactive FAT with the contents of the active
		 * FAT and invalidate the in-memory FAT cache.
		 */
		if (ask(1, "Synchronize secondary FAT with active FAT")) {
			bool sync_ok = true;

			remaining = (size_t)chk->boot.fat_length *
			    chk->boot.sector_size;
			off = 0;

			while (remaining > 0) {
				size_t to_write = MIN(remaining, chunk_size);
				ssize_t n;

				n = pread(chk->fd, buf_act, to_write,
				    active_start + off);
				if (n != (ssize_t)to_write) {
					pwarn("Cannot read active FAT for "
					    "synchronization: %s\n",
					    strerror(errno));
					sync_ok = false;
					break;
				}
				n = pwrite(chk->fd, buf_act, to_write,
				    inactive_start + off);
				if (n != (ssize_t)to_write) {
					pwarn("Cannot write inactive FAT for "
					    "synchronization: %s\n",
					    strerror(errno));
					sync_ok = false;
					break;
				}
				remaining -= to_write;
				off += to_write;
			}
			chk->fat_cache_off = -1;
			chk->fat_cache_valid = 0;
			if (sync_ok)
				mod |= FSFATMOD;
			else
				mod |= FSERROR;
		} else
			mod |= FSERROR;
	}

	free(buf_act);
	free(buf_inact);
	return (mod);
}

/*
 * Mark cluster cn as referenced by owner in the in-memory used bitmap.
 *
 * Detects cross-linked clusters (referenced more than once) and records them
 * in the duplicate bitmap.
 *
 * Returns FSOK, or FSERROR on invalid or duplicate cluster.
 */
int
mark_cluster_used(struct exfat_chk *chk, uint32_t cn, const char *owner)
{
	uint32_t idx;
	uint8_t mask;

	if (!EXFAT_CLUSTER_VALID(chk, cn)) {
		pwarn("Invalid cluster %u referenced by %s "
		    "(heap has %u clusters)\n",
		    cn, owner, chk->boot.cluster_count);
		return (FSERROR);
	}

	idx = EXFAT_CNTOI(cn) / 8;
	mask = 1U << (EXFAT_CNTOI(cn) % 8);

	if (chk->used_bitmap[idx] & mask) {
		chk->dup_bitmap[idx] |= mask;
		pwarn("Cluster %u cross-linked (multiple references, latest "
		    "from %s)\n", cn, owner);
		return (FSERROR);
	}

	chk->used_bitmap[idx] |= mask;
	return (FSOK);
}

/*
 * Test whether cluster cn has been marked as referenced in the used bitmap.
 *
 * Returns true if referenced, false otherwise.
 */
bool
is_cluster_used(const struct exfat_chk *chk, uint32_t cn)
{
	uint32_t idx;
	uint8_t mask;

	if (!EXFAT_CLUSTER_VALID(chk, cn))
		return (false);

	idx = EXFAT_CNTOI(cn) / 8;
	mask = 1U << (EXFAT_CNTOI(cn) % 8);

	return ((chk->used_bitmap[idx] & mask) != 0);
}

/*
 * Verify cluster allocations against the on-disk Allocation Bitmap.
 *
 * Identifies orphaned allocations (allocated on disk but unreferenced) and
 * missing allocations (referenced in directory tree but unallocated on disk).
 * Prompts user to fix discrepancies.
 *
 * Returns FSOK, FSFATMOD, FSERROR, or FSFATAL.
 */
int
check_clusters(struct exfat_chk *chk)
{
	uint64_t orphans = 0;
	uint64_t missing = 0;
	uint64_t crosslinked = 0;
	uint32_t c;
	int mod = FSOK;

	chk->clusters_free = 0;
	chk->clusters_bad = 0;

	/*
	 * Phase 1: Allocation audit and discrepancy classification.
	 *
	 * Scan the cluster heap, tallying bad clusters, cross-linked
	 * clusters (dup_bitmap), unreferenced allocations (orphans),
	 * and unrecorded in-use clusters (missing from disk_bitmap).
	 */
	for (c = 0; c < chk->boot.cluster_count; c++) {
		uint32_t val;
		uint32_t idx = c / 8;
		uint8_t mask = 1U << (c % 8);
		bool in_disk = (chk->disk_bitmap[idx] & mask) != 0;
		bool in_used = (chk->used_bitmap[idx] & mask) != 0;
		bool in_dup  = (chk->dup_bitmap[idx] & mask) != 0;
		bool is_bad = false;

		if (fat_get(chk, EXFAT_ITOCN(c), &val) == 0 &&
		    EXFAT_FAT_IS_BAD(val)) {
			chk->clusters_bad++;
			is_bad = true;
		}

		if (in_dup)
			crosslinked++;

		if (!in_used && !is_bad)
			chk->clusters_free++;

		if (in_disk && !in_used && !is_bad)
			orphans++;
		else if (!in_disk && (in_used || is_bad))
			missing++;
	}

	/*
	 * Phase 2: Cross-linked cluster reporting.
	 */
	if (crosslinked > 0) {
		pwarn("%ju cluster(s) are cross-linked across multiple files\n",
		    crosslinked);
		mod |= FSERROR;
	}

	/*
	 * Phase 3: Orphaned cluster remediation.
	 *
	 * Interactively reconnect orphaned chains into LOST.DIR or clear
	 * bits in the disk allocation bitmap.
	 */
	if (orphans > 0) {
		pwarn("%ju orphaned cluster(s) marked allocated in bitmap "
		    "but unreferenced\n", orphans);
		if (ask(1, "Reconnect orphaned clusters to LOST.DIR")) {
			mod |= reconnect_orphans(chk);
			chk->clusters_free = 0;
			for (c = 0; c < chk->boot.cluster_count; c++) {
				uint32_t idx = c / 8;
				uint8_t mask = 1U << (c % 8);
				uint32_t val;
				bool is_bad = (fat_get(chk, EXFAT_ITOCN(c),
				    &val) == 0 && EXFAT_FAT_IS_BAD(val));

				if (!(chk->used_bitmap[idx] & mask) && !is_bad)
					chk->clusters_free++;
			}
		} else if (ask(1,
		    "Clear orphaned clusters in allocation bitmap")) {
			for (c = 0; c < chk->boot.cluster_count; c++) {
				uint32_t idx = c / 8;
				uint8_t mask = 1U << (c % 8);
				uint32_t val;
				bool is_bad = (fat_get(chk, EXFAT_ITOCN(c),
				    &val) == 0 && EXFAT_FAT_IS_BAD(val));

				if ((chk->disk_bitmap[idx] & mask) &&
				    !(chk->used_bitmap[idx] & mask) && !is_bad)
					chk->disk_bitmap[idx] &= ~mask;
			}
			mod |= FSFATMOD;
		} else
			mod |= FSERROR;
	}

	/*
	 * Phase 4: Missing in-use or bad cluster remediation.
	 *
	 * Mark unrecorded referenced or bad clusters as allocated in the
	 * bitmap.
	 */
	if (missing > 0) {
		pwarn("%ju cluster(s) marked free in bitmap but in use\n",
		    missing);
		if (ask(1, "Mark in-use clusters as allocated in bitmap")) {
			for (c = 0; c < chk->boot.cluster_count; c++) {
				uint32_t idx = c / 8;
				uint8_t mask = 1U << (c % 8);
				uint32_t val;
				bool is_bad = (fat_get(chk, EXFAT_ITOCN(c),
				    &val) == 0 && EXFAT_FAT_IS_BAD(val));

				if (!(chk->disk_bitmap[idx] & mask) &&
				    ((chk->used_bitmap[idx] & mask) || is_bad))
					chk->disk_bitmap[idx] |= mask;
			}
			mod |= FSFATMOD;
		} else
			mod |= FSERROR;
	}

	/*
	 * Phase 5: Bitmap disk commitment.
	 *
	 * Write the corrected allocation bitmap back to disk
	 * cluster-by-cluster.
	 */
	if ((mod & FSFATMOD) && !rdonly) {
		int num_bm = (chk->boot.number_of_fats == 2 &&
		    chk->bitmap2_cluster != 0) ? 2 : 1;

		for (int b = 0; b < num_bm; b++) {
			uint32_t curr_cn = (b == 0) ? chk->bitmap_cluster :
			    chk->bitmap2_cluster;
			size_t remaining = (b == 0) ? chk->bitmap_len :
			    chk->bitmap2_len;
			size_t offset = 0;

			while (remaining > 0 &&
			    EXFAT_CLUSTER_VALID(chk, curr_cn)) {
				size_t to_write = MIN(remaining,
				    chk->boot.cluster_size);
				uint8_t *cbuf = malloc(chk->boot.cluster_size);

				if (cbuf == NULL) {
					perr("Out of memory writing "
					    "allocation bitmap");
					mod |= FSFATAL;
					break;
				}

				memset(cbuf, 0, chk->boot.cluster_size);
				memcpy(cbuf, chk->disk_bitmap + offset,
				    to_write);

				if (write_cluster(chk, curr_cn, cbuf) != 0) {
					free(cbuf);
					mod |= FSFATAL;
					break;
				}
				free(cbuf);

				remaining -= to_write;
				offset += to_write;

				if (remaining > 0) {
					uint32_t next_cn;

					if (fat_get(chk, curr_cn,
					    &next_cn) != 0) {
						mod |= FSFATAL;
						break;
					}
					curr_cn = next_cn;
				}
			}
			if ((mod & FSFATAL) != 0)
				break;
			if (remaining > 0) {
				pwarn("Allocation bitmap cluster chain "
				    "truncated while committing\n");
				mod |= FSFATAL;
				break;
			}
		}
	}

	return (mod);
}
