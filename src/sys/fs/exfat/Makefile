KMOD=	exfat
SRCS=	vnode_if.h \
	exfat_fat.c exfat_lookup.c exfat_node.c exfat_subr.c exfat_unicode.c exfat_vfsops.c exfat_vnops.c

.if defined(INVARIANTS)
CFLAGS+=	-DINVARIANTS -DINVARIANT_SUPPORT -DDIAGNOSTIC
.endif
.if defined(WITNESS)
CFLAGS+=	-DWITNESS -DWITNESS_SKIPSPIN -DDEBUG_LOCKS -DDEBUG_VFS_LOCKS
.endif

WARNS=	5

CFLAGS+=	-I../..

.include <bsd.kmod.mk>
