#!/usr/local/bin/bash

set -e

DIR=$1
if [ "${DIR}" = "" ]; then
	DIR=/usr/local
fi

[ -e /usr/sbin/kldxref ] || exit 1

[ ! -f /boot/modules/exfat.ko ] || /bin/rm /boot/modules/exfat.ko
/usr/sbin/kldxref /boot/modules

[ ! -f ${DIR}/man/man4/exfat.4 ] || /bin/rm ${DIR}/man/man4/exfat.4
[ ! -f ${DIR}/man/man4/exfat.4.gz ] || /bin/rm ${DIR}/man/man4/exfat.4.gz

[ ! -f ${DIR}/sbin/newfs_exfat ] || /bin/rm ${DIR}/sbin/newfs_exfat
[ ! -f ${DIR}/sbin/mount_exfat ] || /bin/rm ${DIR}/sbin/mount_exfat
[ ! -f ${DIR}/sbin/fsck_exfat ] || /bin/rm ${DIR}/sbin/fsck_exfat

[ ! -f ${DIR}/man/man8/newfs_exfat.8 ] || /bin/rm ${DIR}/man/man8/newfs_exfat.8
[ ! -f ${DIR}/man/man8/newfs_exfat.8.gz ] || /bin/rm ${DIR}/man/man8/newfs_exfat.8.gz
[ ! -f ${DIR}/man/man8/mount_exfat.8 ] || /bin/rm ${DIR}/man/man8/mount_exfat.8
[ ! -f ${DIR}/man/man8/mount_exfat.8.gz ] || /bin/rm ${DIR}/man/man8/mount_exfat.8.gz
[ ! -f ${DIR}/man/man8/fsck_exfat.8 ] || /bin/rm ${DIR}/man/man8/fsck_exfat.8
[ ! -f ${DIR}/man/man8/fsck_exfat.8.gz ] || /bin/rm ${DIR}/man/man8/fsck_exfat.8.gz

echo "uninstall success"
