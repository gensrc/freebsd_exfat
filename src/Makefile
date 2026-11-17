SUBDIRS = sys/fs/exfat sbin/newfs_exfat sbin/mount_exfat sbin/fsck_exfat

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@
clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $@; \
	done
