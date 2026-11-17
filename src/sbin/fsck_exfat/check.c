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
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fsck_exfat.h"
#include "fsutil.h"

/*
 * Top-level consistency check and repair driver for an exFAT filesystem.
 *
 * Coordinates checking phases:
 * Phase 1: check_boot() & check_fat_mirror() - Verify and synchronize Main
 *          and Backup boot regions; check FAT mirrors.
 * Phase 2: scan_root_metadata() - Read bitmap, up-case table, and label.
 * Phase 3: check_dirtree() - Traverse directory tree, validate entries,
 *          and track referenced clusters.
 * Phase 4: check_clusters() - Compare used clusters against allocation
 *          bitmap, prompt to reconnect_orphans() into LOST.DIR or clear them.
 * Post:    write_boot_clean() - Clear dirty volume flag if repair succeeds.
 *
 * Returns exit status bitmask (FSOK, FSBOOTMOD, FSDIRMOD, FSFATMOD, etc.).
 */
int
checkfilesys(const char *fname)
{
	struct exfat_chk chk;
	size_t bitmap_bytes;
	int64_t freebytes;
	int mod = FSOK;
	int ret = FSCK_EXIT_ERROR;
	char freestr[16];

	memset(&chk, 0, sizeof(chk));
	chk.fat_cache_off = -1;

	rdonly = alwaysno;
	if (!preen)
		printf("** %s\n", fname);

	chk.fd = open(fname, rdonly ? O_RDONLY : O_RDWR);
	if (chk.fd < 0 && !rdonly) {
		chk.fd = open(fname, O_RDONLY);
		if (chk.fd >= 0)
			pwarn(" (NO WRITE)\n");
		rdonly = 1;
	}

	if (chk.fd < 0) {
		perr("Can't open `%s': %s", fname, strerror(errno));
		return (FSCK_EXIT_ERROR);
	}

	/* Phase 1: Boot Sector & Volume Boot Record */
	if (!preen)
		printf("** Phase 1 - Verifying Boot Sector and Volume Boot "
		    "Record\n");

	mod |= check_boot(&chk);
	if (mod & FSFATAL) {
		close(chk.fd);
		return (FSCK_EXIT_ERROR);
	}

	/* Skip clean filesystem if preening and force was not specified */
	if (preen && !force && (mod & (FSBOOTMOD | FSERROR)) == 0 &&
	    !(chk.boot.volume_flags & EXFAT_VOL_DIRTY)) {
		printf("%s: FILESYSTEM CLEAN; SKIPPING CHECKS\n", fname);
		close(chk.fd);
		return (FSCK_EXIT_OK);
	}

	/* Allocate cluster tracking bitmaps */
	bitmap_bytes = (size_t)howmany((uint64_t)chk.boot.cluster_count, 8);
	chk.used_bitmap = calloc(1, bitmap_bytes);
	chk.dup_bitmap = calloc(1, bitmap_bytes);
	if (chk.used_bitmap == NULL || chk.dup_bitmap == NULL) {
		perr("Out of memory allocating cluster tracking bitmaps");
		free(chk.used_bitmap);
		free(chk.dup_bitmap);
		close(chk.fd);
		return (FSCK_EXIT_ERROR);
	}

	/* Check and synchronize FAT mirrors if multiple FATs exist */
	mod |= check_fat_mirror(&chk);
	if (mod & FSFATAL)
		goto out;

	/* Phase 2: Scanning Root Metadata (Bitmap, Up-Case Table, Label) */
	if (!preen)
		printf("** Phase 2 - Scanning Volume Metadata\n");

	mod |= scan_root_metadata(&chk);
	if (mod & FSFATAL)
		goto out;

	/* Phase 3: Directory Tree and Entry Sets */
	if (!preen)
		printf(
		    "** Phase 3 - Checking Directory Tree and File Streams\n");

	mod |= check_dirtree(&chk);
	if (mod & FSFATAL)
		goto out;

	/* Phase 4: Cluster Allocation Consistency */
	if (!preen)
		printf("** Phase 4 - Checking Cluster Allocation and "
		    "Consistency\n");

	mod |= check_clusters(&chk);
	if (mod & FSFATAL)
		goto out;

	/* Print summary */
	freebytes = (int64_t)chk.clusters_free * chk.boot.cluster_size;
#ifdef HAVE_LIBUTIL_H
	humanize_number(freestr, sizeof(freestr), freebytes, "",
	    HN_AUTOSCALE, HN_DECIMAL | HN_IEC_PREFIXES);
	pwarn("%ju files, %ju directories, %sB free (%ju clusters)\n",
	    chk.num_files, chk.num_dirs, freestr, chk.clusters_free);
#else
	snprintf(freestr, sizeof(freestr), "%jd KiB",
	    (intmax_t)freebytes / 1024);
	pwarn("%ju files, %ju directories, %s free (%ju clusters)\n",
	    chk.num_files, chk.num_dirs, freestr, chk.clusters_free);
#endif
	if (chk.clusters_bad > 0)
		pwarn("%ju bad cluster(s)\n", chk.clusters_bad);

	/* Mark volume clean and commit boot changes if requested */
	if ((mod & FSERROR) == 0) {
		if ((mod & (FSDIRTY | FSBOOTMOD | FSFATMOD)) != 0) {
			if ((mod & FSDIRTY) != 0) {
				if (ask(1, "MARK FILE SYSTEM CLEAN")) {
					int clean_res;

					pwarn("MARKING FILE SYSTEM CLEAN\n");
					clean_res = write_boot_clean(&chk);
					mod |= clean_res;
					if ((clean_res & (FSERROR | FSFATAL))
					    == 0)
						mod &= ~FSDIRTY;
				}
			} else
				mod |= write_boot_clean(&chk);
		}
		if ((mod & (FSDIRTY | FSERROR | FSFATAL)) != 0)
			ret = FSCK_EXIT_UNCORRECTED;
		else
			ret = (mod & (FSBOOTMOD | FSDIRMOD | FSFATMOD)) ?
			    FSCK_EXIT_MODIFIED : FSCK_EXIT_OK;
	} else
		ret = FSCK_EXIT_UNCORRECTED;

out:
	free(chk.disk_bitmap);
	free(chk.used_bitmap);
	free(chk.dup_bitmap);
	free(chk.upcase_table);
	free(chk.fat_cache);
	close(chk.fd);

	if (mod & (FSBOOTMOD | FSDIRMOD | FSFATMOD))
		pwarn("\n***** FILE SYSTEM WAS MODIFIED *****\n");

	return (ret);
}
