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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fsck_exfat.h"
#include "fsutil.h"

int alwaysno = 0;
int alwaysyes = 0;
int preen = 0;
int rdonly = 0;
int verbose = 0;
int force = 0;

static void usage(void) __dead2;

/*
 * Print fsck_exfat usage synopsis to stderr and exit with error.
 */
static void
usage(void)
{
	fprintf(stderr, "%s\n%s\n%s\n%s\n",
	    "usage: fsck_exfat -p [-fv] filesystem ...",
	    "       fsck_exfat [-fnyv] filesystem ...",
	    "       fsck_exfat -l filesystem ...",
	    "       fsck_exfat -L label filesystem ...");
	exit(FSCK_EXIT_USAGE);
}

/*
 * Prompt the user for yes/no confirmation with formatted message fmt.
 *
 * Honors non-interactive flags:
 * - In preen mode (-p), answers def automatically and outputs "FIXED\n".
 * - If alwaysyes (-y), alwaysno (-n), or rdonly is active, resolves without
 *   interactive input.
 *
 * Returns 1 for 'yes', 0 for 'no'.
 */
int
ask(int def, const char *fmt, ...)
{
	va_list ap;
	char prompt[256];
	int c;

	if (alwaysyes || alwaysno || rdonly)
		def = (alwaysyes && !rdonly && !alwaysno);

	if (preen) {
		if (def)
			pwarn("FIXED\n");
		return (def);
	}

	va_start(ap, fmt);
	vsnprintf(prompt, sizeof(prompt), fmt, ap);
	va_end(ap);

	if (alwaysyes || alwaysno || rdonly) {
		printf("%s? %s\n", prompt, def ? "yes" : "no");
		return (def);
	}

	do {
		printf("%s? [yn] ", prompt);
		fflush(stdout);
		c = getchar();
		if (c == EOF)
			return (def);
		while (c != '\n' && getchar() != '\n')
			if (feof(stdin))
				return (def);
	} while (c != 'y' && c != 'Y' && c != 'n' && c != 'N');

	return (c == 'y' || c == 'Y');
}

int
main(int argc, char **argv)
{
	const char *setlabel = NULL;
	int ch, ret = FSCK_EXIT_OK, erg, getlabel = 0;

	while ((ch = getopt(argc, argv, "BCfFlL:npyv")) != -1) {
		switch (ch) {
		case 'B':
		case 'C':
			/* Ignored for fsck(8) compatibility */
			break;
		case 'F':
			/*
			 * exFAT filesystems cannot be cleaned in the
			 * background.  Return non-zero exit code so fsck(8)
			 * knows foreground checking is required.
			 */
			exit(FSCK_EXIT_NO_BG);
		case 'f':
			force = 1;
			break;
		case 'l':
			getlabel = 1;
			break;
		case 'L':
			setlabel = optarg;
			break;
		case 'n':
			alwaysno = 1;
			alwaysyes = 0;
			break;
		case 'y':
			alwaysyes = 1;
			alwaysno = 0;
			break;
		case 'p':
			preen = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			break;
		}
	}

	if (getlabel && setlabel != NULL) {
		fprintf(stderr,
		    "fsck_exfat: options -l and -L are mutually exclusive\n");
		usage();
	}
	if ((getlabel || setlabel != NULL) &&
	    (preen || alwaysno || alwaysyes)) {
		fprintf(stderr, "fsck_exfat: "
		    "-l/-L cannot be combined with -p, -n, or -y\n");
		usage();
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	if (getlabel) {
		rdonly = 1;
		while (argc > 0) {
			struct exfat_chk chk;
			char label[EXFAT_MAX_LABEL_CHARS * 4 + 1];

			memset(&chk, 0, sizeof(chk));
			chk.fat_cache_off = -1;
			chk.fd = open(*argv, O_RDONLY);
			if (chk.fd < 0) {
				perr("Can't open `%s': %s", *argv,
				    strerror(errno));
				ret = FSCK_EXIT_ERROR;
				argc--;
				argv++;
				continue;
			}
			if (check_boot(&chk) & FSFATAL) {
				close(chk.fd);
				ret = FSCK_EXIT_ERROR;
				argc--;
				argv++;
				continue;
			}
			if (get_vol_label(&chk, label, sizeof(label)) != 0) {
				free(chk.fat_cache);
				close(chk.fd);
				ret = FSCK_EXIT_ERROR;
				argc--;
				argv++;
				continue;
			}
			printf("%s\n", label);
			free(chk.fat_cache);
			close(chk.fd);
			argc--;
			argv++;
		}
		return (ret);
	}

	if (setlabel != NULL) {
		while (argc > 0) {
			struct exfat_chk chk;

			memset(&chk, 0, sizeof(chk));
			chk.fat_cache_off = -1;
			chk.fd = open(*argv, O_RDWR);
			if (chk.fd < 0) {
				perr("Can't open `%s': %s", *argv,
				    strerror(errno));
				ret = FSCK_EXIT_ERROR;
				argc--;
				argv++;
				continue;
			}
			if (check_boot(&chk) & FSFATAL) {
				close(chk.fd);
				ret = FSCK_EXIT_ERROR;
				argc--;
				argv++;
				continue;
			}
			if (set_vol_label(&chk, setlabel) != 0) {
				free(chk.fat_cache);
				close(chk.fd);
				ret = FSCK_EXIT_ERROR;
				argc--;
				argv++;
				continue;
			}
			free(chk.fat_cache);
			close(chk.fd);
			argc--;
			argv++;
		}
		return (ret);
	}

	while (argc > 0) {
		setcdevname(*argv, preen);
		erg = checkfilesys(*argv);
		if (erg > ret)
			ret = erg;
		argc--;
		argv++;
	}

	return (ret);
}
