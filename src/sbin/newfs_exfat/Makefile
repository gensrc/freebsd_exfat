.include <bsd.own.mk>

PROG=	newfs_exfat
SRCS=	newfs_exfat.c mkfs_exfat.c upcase.c ../../sys/fs/exfat/exfat_unicode.c
MAN=	newfs_exfat.8

WARNS=	5

CFLAGS+=	-I../../sys

LIBADD+=	util

.include <bsd.prog.mk>
