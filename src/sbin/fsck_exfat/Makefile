.include <bsd.own.mk>

PROG=	fsck_exfat
SRCS=	fsck_exfat.c boot.c check.c dir.c fat.c ../fsck/fsutil.c ../../sys/fs/exfat/exfat_unicode.c
MAN=	fsck_exfat.8

WARNS=	5

CFLAGS+=	-I../fsck -I../../sys

LIBADD+=	util

.include <bsd.prog.mk>
