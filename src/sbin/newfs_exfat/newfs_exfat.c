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
#include <err.h>
#include <errno.h>
#include <libutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fs/exfat/exfat_unicode.h>

#include "newfs_exfat.h"

static void usage(void) __dead2;

/*
 * Print newfs_exfat command usage synopsis to stderr and exit with error.
 */
static void
usage(void)
{
	fprintf(stderr,
	    "usage: newfs_exfat [-Nv] [-C create-size] [-c cluster-size]\n"
	    "                   [-I volume-id] [-L label]\n"
	    "                   [-p partition-offset] [-S sector-size]\n"
	    "                   [-s size] special\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct exfat_mkfs_opts opts;
	uint16_t utf16_label[EXFAT_MAX_VOLUME_LABEL_CHARS];
	int64_t val;
	unsigned long ul;
	char *ep;
	size_t nchars;
	int ch, error;

	memset(&opts, 0, sizeof(opts));

	while ((ch = getopt(argc, argv, "C:c:I:L:Np:S:s:v")) != -1) {
		switch (ch) {
		case 'C':
			if (expand_number(optarg, &val) != 0 || val <= 0)
				errx(1, "Invalid create size: %s", optarg);
			opts.create_size = (off_t)val;
			break;
		case 'c':
			if (expand_number(optarg, &val) != 0 || val <= 0 ||
			    val > UINT32_MAX)
				errx(1, "Invalid cluster size: %s", optarg);
			opts.cluster_size = (uint32_t)val;
			break;
		case 'I':
			errno = 0;
			ul = strtoul(optarg, &ep, 0);
			if (errno != 0 || *optarg == '\0' || *ep != '\0' ||
			    ul > UINT32_MAX)
				errx(1, "Invalid volume ID: %s", optarg);
			opts.volume_serial = (uint32_t)ul;
			opts.serial_set = true;
			break;
		case 'L':
			nchars = 0;
			error = exfat_utf8_to_utf16(optarg, strlen(optarg),
			    utf16_label, EXFAT_MAX_VOLUME_LABEL_CHARS, &nchars);
			if (error == ENAMETOOLONG)
				errx(1,
				    "Volume label '%s' exceeds %d characters",
				    optarg, EXFAT_MAX_VOLUME_LABEL_CHARS);
			if (error != 0)
				errx(1,
				    "Volume label '%s' contains invalid UTF-8 "
				    "sequence", optarg);
			if (!exfat_is_valid_label(utf16_label, nchars))
				errx(1,
				    "Volume label '%s' contains invalid "
				    "character", optarg);
			opts.volume_label = optarg;
			break;
		case 'N':
			opts.no_create = true;
			break;
		case 'p':
			if (expand_number(optarg, &val) != 0 || val < 0)
				errx(1, "Invalid partition offset: %s", optarg);
			opts.partition_offset = (uint64_t)val;
			break;
		case 'S':
			errno = 0;
			ul = strtoul(optarg, &ep, 0);
			if (errno != 0 || *optarg == '\0' || *ep != '\0' ||
			    ul > UINT32_MAX)
				errx(1, "Invalid sector size: %s", optarg);
			opts.bytes_per_sector = (uint32_t)ul;
			break;
		case 's':
			if (expand_number(optarg, &val) != 0 || val <= 0)
				errx(1, "Invalid volume size: %s", optarg);
			opts.volume_size = (off_t)val;
			break;
		case 'v':
			opts.verbose = true;
			break;
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	opts.special = argv[0];

	return (mkfs_exfat(&opts));
}
