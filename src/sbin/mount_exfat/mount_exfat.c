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
#include <sys/mount.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <libutil.h>
#include <mntopts.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#define _PATH_MOUNTDPID	"/var/run/mountd.pid"

static gid_t	a_gid(const char *);
static uid_t	a_uid(const char *);
static mode_t	a_mask(const char *);
static void	usage(void) __dead2;

int
main(int argc, char **argv)
{
	struct iovec *iov = NULL;
	struct stat sb;
	char *dev, *dir, *opt, *p, *s, *val, mntpath[MAXPATHLEN];
	char fstype[] = "exfat";
	char errmsg[255] = {0};
	mode_t dirmask = 0, mask = 0;
	gid_t gid = 0;
	uid_t uid = 0;
	int c, iovlen = 0, set_dirmask, set_gid, set_mask, set_uid, update;

	set_gid = set_uid = set_mask = set_dirmask = update = 0;

	while ((c = getopt(argc, argv, "u:g:m:M:o:rw")) != -1) {
		switch (c) {
		case 'u':
			uid = a_uid(optarg);
			set_uid = 1;
			break;
		case 'g':
			gid = a_gid(optarg);
			set_gid = 1;
			break;
		case 'm':
			mask = a_mask(optarg);
			set_mask = 1;
			break;
		case 'M':
			dirmask = a_mask(optarg);
			set_dirmask = 1;
			break;
		case 'o':
			s = optarg;
			while ((opt = strsep(&s, ",")) != NULL) {
				if (*opt == '\0')
					continue;
				p = strchr(opt, '=');
				val = NULL;
				if (p != NULL) {
					*p = '\0';
					val = p + 1;
				}
				if (strcmp(opt, "uid") == 0) {
					if (val == NULL)
						errx(EX_USAGE,
						    "option 'uid' requires a "
						    "value");
					uid = a_uid(val);
					set_uid = 1;
				} else if (strcmp(opt, "gid") == 0) {
					if (val == NULL)
						errx(EX_USAGE,
						    "option 'gid' requires a "
						    "value");
					gid = a_gid(val);
					set_gid = 1;
				} else if (strcmp(opt, "mask") == 0) {
					if (val == NULL)
						errx(EX_USAGE,
						    "option 'mask' requires a "
						    "value");
					mask = a_mask(val);
					set_mask = 1;
				} else if (strcmp(opt, "dirmask") == 0) {
					if (val == NULL)
						errx(EX_USAGE,
						    "option 'dirmask' requires "
						    "a value");
					dirmask = a_mask(val);
					set_dirmask = 1;
				} else {
					if (strcmp(opt, "update") == 0)
						update = 1;
					build_iovec(&iov, &iovlen, opt,
					    val != NULL ? val : strdup(""),
					    (size_t)-1);
				}
			}
			break;
		case 'r':
			build_iovec(&iov, &iovlen, "ro", NULL, 0);
			break;
		case 'w':
			build_iovec(&iov, &iovlen, "noro", NULL, 0);
			break;
		case '?':
		default:
			usage();
			break;
		}
	}

	if (optind + 2 != argc)
		usage();

	if (set_mask && !set_dirmask) {
		dirmask = mask;
		set_dirmask = 1;
	} else if (set_dirmask && !set_mask) {
		mask = dirmask;
		set_mask = 1;
	}

	dev = argv[optind];
	dir = argv[optind + 1];

	/*
	 * Resolve the mountpoint with realpath(3) and remove unnecessary
	 * slashes from the devicename if there are any.
	 */
	if (checkpath(dir, mntpath) != 0)
		err(EX_USAGE, "%s", mntpath);
	(void)rmslashes(dev, dev);

	if (!update && (!set_gid || !set_uid || !set_mask)) {
		if (stat(mntpath, &sb) == -1)
			err(EX_OSERR, "stat %s", mntpath);

		if (!set_uid) {
			uid = sb.st_uid;
			set_uid = 1;
		}
		if (!set_gid) {
			gid = sb.st_gid;
			set_gid = 1;
		}
		if (!set_mask) {
			mask = dirmask =
			    sb.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
			set_mask = set_dirmask = 1;
		}
	}

	build_iovec(&iov, &iovlen, "fstype", fstype, (size_t)-1);
	build_iovec(&iov, &iovlen, "fspath", mntpath, (size_t)-1);
	build_iovec(&iov, &iovlen, "from", dev, (size_t)-1);
	build_iovec(&iov, &iovlen, "errmsg", errmsg, sizeof(errmsg));
	if (set_uid)
		build_iovec_argf(&iov, &iovlen, "uid", "%u", uid);
	if (set_gid)
		build_iovec_argf(&iov, &iovlen, "gid", "%u", gid);
	if (set_mask)
		build_iovec_argf(&iov, &iovlen, "mask", "%u", mask);
	if (set_dirmask)
		build_iovec_argf(&iov, &iovlen, "dirmask", "%u", dirmask);

	if (nmount(iov, iovlen, 0) < 0) {
		if (errmsg[0] != '\0')
			err(1, "%s: %s", dev, errmsg);
		else
			err(1, "%s", dev);
	}

	/*
	 * If the mount was successful, and done by root, tell mountd the
	 * good news.
	 */
	if (getuid() == 0)
		pidfile_signal(_PATH_MOUNTDPID, SIGHUP, NULL);

	exit(0);
}

/*
 * Parse a group identifier from a name or decimal string.
 *
 * Checks getgrnam(3) first, falling back to strtoul(3).  Exits with EX_NOUSER
 * if the group name or numeric ID is invalid or out of range.
 *
 * Returns parsed gid_t value.
 */
static gid_t
a_gid(const char *s)
{
	struct group *gr;
	char *ep;
	unsigned long val;

	if ((gr = getgrnam(s)) != NULL)
		return (gr->gr_gid);

	errno = 0;
	val = strtoul(s, &ep, 10);
	if (*s == '\0' || *ep != '\0' || errno == ERANGE || val > GID_MAX)
		errx(EX_NOUSER, "unknown group id: %s", s);

	return ((gid_t)val);
}

/*
 * Parse a user identifier from a user name or decimal string.
 *
 * Checks getpwnam(3) first, falling back to strtoul(3).  Exits with EX_NOUSER
 * if the user name or numeric ID is invalid or out of range.
 *
 * Returns parsed uid_t value.
 */
static uid_t
a_uid(const char *s)
{
	struct passwd *pw;
	char *ep;
	unsigned long val;

	if ((pw = getpwnam(s)) != NULL)
		return (pw->pw_uid);

	errno = 0;
	val = strtoul(s, &ep, 10);
	if (*s == '\0' || *ep != '\0' || errno == ERANGE || val > UID_MAX)
		errx(EX_NOUSER, "unknown user id: %s", s);

	return ((uid_t)val);
}

/*
 * Parse an octal file mode mask from string s.
 *
 * Converts octal digits using strtol(3).  Exits with EX_USAGE if the string
 * is empty, contains non-octal characters, or specifies invalid bits.
 *
 * Returns parsed mode_t value.
 */
static mode_t
a_mask(const char *s)
{
	int done;
	long rv;
	char *ep;

	done = 0;
	rv = -1;
	if (*s >= '0' && *s <= '7') {
		done = 1;
		errno = 0;
		rv = strtol(s, &ep, 8);
	}
	if (!done || errno != 0 || rv < 0 || *ep != '\0' || (rv & ~07777) != 0)
		errx(EX_USAGE, "invalid file mode: %s", s);
	return ((mode_t)rv);
}

/*
 * Print mount_exfat usage synopsis to stderr and exit with EX_USAGE.
 */
static void
usage(void)
{
	fprintf(stderr, "%s\n%s\n",
	    "usage: mount_exfat [-r] [-w] [-g gid] [-M mask] [-m mask] "
	    "[-o options]",
	    "                   [-u uid] special node");
	exit(EX_USAGE);
}
