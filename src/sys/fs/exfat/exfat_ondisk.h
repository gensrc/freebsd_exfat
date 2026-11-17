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

#ifndef _FS_EXFAT_EXFAT_ONDISK_H_
#define _FS_EXFAT_EXFAT_ONDISK_H_

#include <sys/types.h>
#include <sys/endian.h>
#ifndef _KERNEL
#include <stdbool.h>
#endif

/*
 * exFAT Volume Boot Record (VBR) Constants
 */
#define EXFAT_FS_NAME			"EXFAT   "
#define EXFAT_FS_REVISION		0x0100
#define EXFAT_FS_REVISION_MAJOR		0x01
#define EXFAT_BOOT_SIGNATURE		0xAA55
#define EXFAT_BOOT_JMP_0		0xEB
#define EXFAT_BOOT_JMP_1		0x76
#define EXFAT_BOOT_JMP_2		0x90
#define EXFAT_DRIVE_SELECT_HD		0x80
#define EXFAT_PERCENT_IN_USE_UNKNOWN	0xFF
#define EXFAT_VOL_FLAGS_OFFSET		106
#define EXFAT_PERCENT_IN_USE_OFFSET	112

/*
 * Boot Region Geometry
 */
#define EXFAT_BOOT_SECTORS_PER_REGION	12
#define EXFAT_BACKUP_BOOT_SECTOR	12
#define EXFAT_BOOT_CHECKSUM_SECTOR	11
#define EXFAT_BOOT_SECTORS_CHECKSUM	11
#define EXFAT_MIN_FAT_OFFSET		24
#define EXFAT_MIN_SECTOR_SHIFT		9
#define EXFAT_MAX_SECTOR_SHIFT		12
#define EXFAT_MAX_CLUSTER_SHIFT		25
#define EXFAT_MAX_CLUSTER_SIZE		(32U * 1024 * 1024)
#define EXFAT_MIN_VOLUME_SIZE		(1ULL * 1024 * 1024)

/*
 * Directory Entry and Name Limits
 */
#define EXFAT_MAX_NAME_CHARS		255
#define EXFAT_CHARS_PER_NAME_ENTRY	15
#define EXFAT_MIN_SECONDARY_COUNT	2
#define EXFAT_MAX_SECONDARY_COUNT	18
#define EXFAT_MAX_NAME_ENTRIES		17
#define EXFAT_MAX_VOLUME_LABEL_CHARS	11
#define EXFAT_DENTRY_SIZE		32
#define EXFAT_MAX_DIR_SIZE		(256ULL * 1024 * 1024)

/*
 * Allocation Bitmap and Up-case Table limits
 */
#define EXFAT_BITMAP_FLAG_SECOND	0x01
#define EXFAT_MAX_BITMAP_SIZE		(512U * 1024 * 1024)	/* 512 MiB */
#define EXFAT_MAX_UPCASE_SIZE		(128U * 1024)		/* 128 KiB */
#define EXFAT_UPCASE_TABLE_CHARS	65536
#define EXFAT_UPCASE_COMPRESSED_FLAG	0xFFFF

/*
 * Sector 0: Main Boot Sector (512 bytes).
 *
 * Defines partition geometry, FAT location, cluster heap layout, and volume
 * parameters per exFAT Spec §3.1.
 */
struct exfat_boot_sector {
	uint8_t		bs_jmp_boot[3];		/* Jump instruction (0xEB, 0x76, 0x90) */
	uint8_t		bs_fs_name[8];		/* "EXFAT   " */
	uint8_t		bs_must_be_zero[53];	/* Must be zero */
	uint64_t	bs_partition_offset;	/* Partition sector offset */
	uint64_t	bs_volume_length;	/* Volume size in sectors */
	uint32_t	bs_fat_offset;		/* First FAT sector offset */
	uint32_t	bs_fat_length;		/* Size of each FAT in sectors */
	uint32_t	bs_cluster_heap_offset;	/* Sector offset of Cluster 2 */
	uint32_t	bs_cluster_count;	/* Total clusters in Cluster Heap */
	uint32_t	bs_root_dir_cluster;	/* First cluster of Root Directory */
	uint32_t	bs_volume_serial;	/* Volume serial number */
	uint16_t	bs_fs_revision;		/* Revision: 0x0100 = 1.00 */
	uint16_t	bs_volume_flags;	/* EXFAT_VOL_* flags */
	uint8_t		bs_bytes_per_sector_shift;	/* 9 (512B) to 12 (4096B) */
	uint8_t		bs_sectors_per_cluster_shift;	/* 0 (1 sector) to max cluster */
	uint8_t		bs_number_of_fats;	/* 1 (standard) or 2 (TexFAT) */
	uint8_t		bs_drive_select;	/* Extended INT 13h drive number */
	uint8_t		bs_percent_in_use;	/* 0-100 or 0xFF (not available) */
	uint8_t		bs_reserved[7];		/* Reserved */
	uint8_t		bs_boot_code[390];	/* Boot code */
	uint16_t	bs_boot_signature;	/* 0xAA55 */
} __packed;

_Static_assert(sizeof(struct exfat_boot_sector) == 512,
    "struct exfat_boot_sector must be 512 bytes");

/*
 * Volume Flags (bs_volume_flags)
 */
#define EXFAT_VOL_ACTIVE_FAT		0x0001	/* 0 = FAT1, 1 = FAT2 */
#define EXFAT_VOL_DIRTY			0x0002	/* Volume is dirty */
#define EXFAT_VOL_MEDIA_FAILURE		0x0004	/* Media failure detected */
#define EXFAT_VOL_CLEAR_TO_ZERO		0x0008	/* Clear to zero required */

/*
 * File Allocation Table (FAT) cluster definitions.
 *
 * In the exFAT architecture (inheriting from legacy FAT), FAT entries 0 and 1
 * are reserved (media descriptor and end-of-chain marker). Cluster allocations
 * in the cluster heap therefore start at EXFAT_FIRST_CLUSTER (cluster 2).
 * Conversely, the cluster heap offset, allocation bitmap, and FAT array
 * indices are 0-based relative to the start of the heap.
 *
 * EXFAT_CNTOI() translates a cluster number (>= 2) to its 0-based heap index.
 * EXFAT_ITOCN() translates a 0-based heap index back to a cluster number.
 */
#define EXFAT_FIRST_CLUSTER		2
#define EXFAT_CNTOI(cn)			((cn) - EXFAT_FIRST_CLUSTER)
#define EXFAT_ITOCN(idx)		((idx) + EXFAT_FIRST_CLUSTER)

/*
 * FAT Table Entry Values (Spec §3.1.7 and §4.1.2)
 *
 * 0xFFFFFFF7 (EXFAT_FAT_BAD) is a sentinel value defined for entries in the
 * FAT table, but not in a field in other structures (such as FirstCluster in
 * directory entries, which is a cluster number within the cluster heap).
 */
#define EXFAT_FAT_FREE			0x00000000U
#define EXFAT_FAT_RESERVED		0x00000001U
#define EXFAT_FAT_BAD			0xFFFFFFF7U
#define EXFAT_FAT_EOF			0xFFFFFFFFU
#define EXFAT_FAT_IS_EOF(cn)		((cn) > EXFAT_FAT_BAD)
#define EXFAT_FAT_IS_BAD(cn)		((cn) == EXFAT_FAT_BAD)
#define EXFAT_MAX_CLUSTER_COUNT		(EXFAT_FAT_BAD - EXFAT_FIRST_CLUSTER)

/*
 * Directory Entry Types
 * Bit 7: InUse (1 = allocated, 0 = deleted / free)
 * Bit 6: TypeCategory (0 = Primary, 1 = Secondary)
 * Bit 5: TypeImportance (0 = Critical, 1 = Benign)
 * Bits 4-0: TypeCode
 */
#define EXFAT_ENTRY_TYPE_IN_USE		0x80
#define EXFAT_ENTRY_TYPE_SECONDARY	0x40
#define EXFAT_ENTRY_TYPE_BENIGN		0x20
#define EXFAT_ENTRY_TYPE_CODE_MASK	0x1F

/* End of Directory Entry */
#define EXFAT_ENTRY_EOD			0x00

/* Critical Primary Entries */
#define EXFAT_ENTRY_BITMAP		0x81	/* Allocation Bitmap */
#define EXFAT_ENTRY_UPCASE		0x82	/* Up-case Table */
#define EXFAT_ENTRY_VOLUME_LABEL	0x83	/* Volume Label */
#define EXFAT_ENTRY_FILE		0x85	/* File Directory Entry */

/* Critical Secondary Entries */
#define EXFAT_ENTRY_STREAM		0xC0	/* Stream Extension Entry */
#define EXFAT_ENTRY_NAME		0xC1	/* File Name Entry */

/* Benign Primary Entries */
#define EXFAT_ENTRY_VOLUME_GUID		0xA0	/* Volume GUID */
#define EXFAT_ENTRY_TEXFAT_PADDING	0xA1	/* TexFAT Padding */

/* Benign Secondary Entries */
#define EXFAT_ENTRY_VENDOR_EXT		0xE0	/* Vendor Extension */
#define EXFAT_ENTRY_VENDOR_ALLOC	0xE1	/* Vendor Allocation */

/*
 * File Attributes (de_file_attributes)
 */
#define EXFAT_ATTR_READ_ONLY		0x0001
#define EXFAT_ATTR_HIDDEN		0x0002
#define EXFAT_ATTR_SYSTEM		0x0004
#define EXFAT_ATTR_DIRECTORY		0x0010
#define EXFAT_ATTR_ARCHIVE		0x0020

/*
 * Stream Extension Flags (se_general_flags)
 *
 * Per Microsoft exFAT Specification Section 7.6.2 (GeneralSecondaryFlags
 * Field of Stream Extension Directory Entry, conforming to Section 6.4.2),
 * Bit 0 (AllocationPossible) describes whether cluster allocation in the
 * Cluster Heap is possible for the entry.  For Stream Extension entries
 * (0xC0), AllocationPossible is always set to 1 unconditionally, even for
 * 0-byte files (where FirstCluster = 0, DataLength = 0, and NoFatChain = 0),
 * because the entry represents an allocatable data stream.  Secondary entries
 * that do not represent cluster allocations (e.g. File Name entries, 0xC1)
 * clear this bit.
 */
#define EXFAT_FLAG_ALLOC_POSSIBLE	0x01	/* Allocation is possible */
#define EXFAT_FLAG_NO_FAT_CHAIN		0x02	/* Contiguous; no FAT chain */

/*
 * TimeZoneOffset on-disk flags and mask (fe_*_tz_offset)
 */
#define EXFAT_TZ_VALID			0x80	/* TimeZoneOffset is valid */
#define EXFAT_TZ_OFFSET_MASK		0x7F	/* 7-bit signed offset */

/*
 * Allocation Bitmap Entry (Type 0x81).
 *
 * Per exFAT Spec §7.1, points to the Allocation Bitmap recording cluster
 * allocation status in the Cluster Heap (1 bit per cluster).
 */
struct exfat_dentry_bitmap {
	uint8_t		bm_type;		/* 0x81 */
	uint8_t		bm_flags;		/* Bit 0: 0 = 1st bitmap, 1 = 2nd bitmap */
	uint8_t		bm_reserved[18];
	uint32_t	bm_first_cluster;	/* First cluster of bitmap */
	uint64_t	bm_data_length;		/* Bitmap size in bytes */
} __packed;

_Static_assert(sizeof(struct exfat_dentry_bitmap) == EXFAT_DENTRY_SIZE,
    "struct exfat_dentry_bitmap must be 32 bytes");

/*
 * Up-case Table Entry (Type 0x82).
 *
 * Per exFAT Spec §7.2, points to the uppercase mapping table used for
 * case-insensitive comparisons and file name hashing.
 */
struct exfat_dentry_upcase {
	uint8_t		uc_type;		/* 0x82 */
	uint8_t		uc_reserved1[3];
	uint32_t	uc_table_checksum;	/* 32-bit checksum of table */
	uint8_t		uc_reserved2[12];
	uint32_t	uc_first_cluster;	/* First cluster of up-case table */
	uint64_t	uc_data_length;		/* Table size in bytes */
} __packed;

_Static_assert(sizeof(struct exfat_dentry_upcase) == EXFAT_DENTRY_SIZE,
    "struct exfat_dentry_upcase must be 32 bytes");

/*
 * Volume Label Entry (Type 0x83).
 *
 * Per exFAT Spec §7.3, records the optional volume label (up to 11 UTF-16
 * characters) in the root directory.
 */
struct exfat_dentry_volume_label {
	uint8_t		vl_type;		/* 0x83 (or 0x03 if deleted) */
	uint8_t		vl_character_count;	/* Number of characters (0 - 11) */
	uint16_t	vl_volume_label[EXFAT_MAX_VOLUME_LABEL_CHARS];
	uint8_t		vl_reserved[8];
} __packed;

_Static_assert(sizeof(struct exfat_dentry_volume_label) == EXFAT_DENTRY_SIZE,
    "struct exfat_dentry_volume_label must be 32 bytes");

/*
 * Volume GUID Entry (Type 0xA0).
 *
 * Per exFAT Spec §7.5, optional benign primary entry recording a 128-bit
 * unique identifier for the volume.
 */
struct exfat_dentry_volume_guid {
	uint8_t		vg_type;		/* 0xA0 */
	uint8_t		vg_secondary_count;	/* 0 */
	uint16_t	vg_set_checksum;
	uint16_t	vg_general_flags;
	uint8_t		vg_guid[16];
	uint8_t		vg_reserved[10];
} __packed;

_Static_assert(sizeof(struct exfat_dentry_volume_guid) == EXFAT_DENTRY_SIZE,
    "struct exfat_dentry_volume_guid must be 32 bytes");

/*
 * TexFAT Padding Directory Entry (Type 0xA1).
 *
 * Per exFAT Spec §7.10, optional benign primary entry used by TexFAT.
 */
struct exfat_dentry_texfat_padding {
	uint8_t		tp_type;		/* 0xA1 */
	uint8_t		tp_secondary_count;	/* 0 */
	uint16_t	tp_set_checksum;
	uint16_t	tp_general_flags;
	uint8_t		tp_reserved[26];
} __packed;

_Static_assert(sizeof(struct exfat_dentry_texfat_padding) == EXFAT_DENTRY_SIZE,
    "struct exfat_dentry_texfat_padding must be 32 bytes");

/*
 * File Directory Entry (Type 0x85 - Primary).
 *
 * Per exFAT Spec §7.4, describes a file or directory's attributes, creation,
 * modification, and access timestamps, and count of secondary entries.
 */
struct exfat_dentry_file {
	uint8_t		fe_type;		/* 0x85 */
	uint8_t		fe_secondary_count;	/* Count of secondary entries following */
	uint16_t	fe_set_checksum;	/* Checksum of entire directory entry set */
	uint16_t	fe_file_attributes;	/* EXFAT_ATTR_* */
	uint16_t	fe_reserved1;
	uint32_t	fe_create_timestamp;	/* Packed MS-DOS timestamp */
	uint32_t	fe_last_modified_timestamp;
	uint32_t	fe_last_access_timestamp;
	uint8_t		fe_create_10ms_increment;	/* 10ms (0 - 199) */
	uint8_t		fe_last_modified_10ms_increment;
	uint8_t		fe_create_tz_offset;	/* Offset from UTC in 15-min intervals */
	uint8_t		fe_last_modified_tz_offset;
	uint8_t		fe_last_access_tz_offset;
	uint8_t		fe_reserved2[7];
} __packed;

_Static_assert(sizeof(struct exfat_dentry_file) == EXFAT_DENTRY_SIZE,
    "struct exfat_dentry_file must be 32 bytes");

/*
 * Stream Extension Directory Entry (Type 0xC0 - Secondary).
 *
 * Per exFAT Spec §7.6, describes the data stream associated with a file or
 * directory, including first cluster, NoFatChain flag, valid data length,
 * total data length, and 16-bit NameHash.
 */
struct exfat_dentry_stream {
	uint8_t		se_type;		/* 0xC0 */
	uint8_t		se_general_flags;	/* EXFAT_FLAG_* */
	uint8_t		se_reserved1;
	uint8_t		se_name_length;		/* File name length in UTF-16 characters */
	uint16_t	se_name_hash;		/* 16-bit hash of up-cased file name */
	uint16_t	se_reserved2;
	uint64_t	se_valid_data_length;	/* Valid data length in bytes */
	uint32_t	se_reserved3;
	uint32_t	se_first_cluster;	/* First cluster of stream */
	uint64_t	se_data_length;		/* Total data length in bytes */
} __packed;

_Static_assert(sizeof(struct exfat_dentry_stream) == EXFAT_DENTRY_SIZE,
    "struct exfat_dentry_stream must be 32 bytes");

/*
 * File Name Directory Entry (Type 0xC1 - Secondary).
 *
 * Per exFAT Spec §7.7, stores up to 15 UTF-16LE characters of a file or
 * directory name.  Multiple entries are chained for names up to 255 chars.
 */
struct exfat_dentry_name {
	uint8_t		ne_type;		/* 0xC1 */
	uint8_t		ne_general_flags;	/* 0 */
	uint16_t	ne_file_name[EXFAT_CHARS_PER_NAME_ENTRY]; /* 15 UTF-16LE chars */
} __packed;

_Static_assert(sizeof(struct exfat_dentry_name) == EXFAT_DENTRY_SIZE,
    "struct exfat_dentry_name must be 32 bytes");

/*
 * Vendor Extension Directory Entry (Type 0xE0 - Secondary).
 *
 * Per exFAT Spec §7.8, optional benign secondary entry storing vendor
 * specific metadata associated with a GUID.
 */
struct exfat_dentry_vendor_ext {
	uint8_t		ve_type;		/* 0xE0 */
	uint8_t		ve_general_flags;	/* 0 */
	uint8_t		ve_vendor_guid[16];
	uint8_t		ve_vendor_defined[14];
} __packed;

_Static_assert(sizeof(struct exfat_dentry_vendor_ext) == EXFAT_DENTRY_SIZE,
    "struct exfat_dentry_vendor_ext must be 32 bytes");

/*
 * Vendor Allocation Directory Entry (Type 0xE1 - Secondary).
 *
 * Per exFAT Spec §7.9, optional benign secondary entry recording an
 * allocated cluster chain and length associated with a vendor GUID.
 */
struct exfat_dentry_vendor_alloc {
	uint8_t		va_type;		/* 0xE1 */
	uint8_t		va_general_flags;	/* EXFAT_FLAG_* */
	uint8_t		va_vendor_guid[16];
	uint8_t		va_custom_defined[2];
	uint32_t	va_first_cluster;
	uint64_t	va_data_length;
} __packed;

_Static_assert(sizeof(struct exfat_dentry_vendor_alloc) == EXFAT_DENTRY_SIZE,
    "struct exfat_dentry_vendor_alloc must be 32 bytes");

/*
 * Generic 32-byte Directory Entry Union.
 *
 * Per exFAT Spec §6.1, every directory entry occupies exactly 32 bytes on
 * disk with the entry type code at byte offset 0.
 */
union exfat_dentry {
	uint8_t					type;
	struct exfat_dentry_file		file;
	struct exfat_dentry_stream		stream;
	struct exfat_dentry_name		name;
	struct exfat_dentry_bitmap		bitmap;
	struct exfat_dentry_upcase		upcase;
	struct exfat_dentry_volume_label	volume_label;
	struct exfat_dentry_volume_guid		volume_guid;
	struct exfat_dentry_texfat_padding	texfat_padding;
	struct exfat_dentry_vendor_ext		vendor_ext;
	struct exfat_dentry_vendor_alloc	vendor_alloc;
	uint8_t					raw[EXFAT_DENTRY_SIZE];
} __packed;

_Static_assert(sizeof(union exfat_dentry) == EXFAT_DENTRY_SIZE,
    "union exfat_dentry must be 32 bytes");

/*
 * Standard exFAT Checksum and Hash Functions
 */

/*
 * Rotate-and-add checksum algorithm for boot sector verification.
 *
 * Per exFAT Spec §3.4, computes the running 32-bit checksum across the
 * first 11 sectors of the Main or Backup Boot Region:
 *   checksum = ((checksum << 31) | (checksum >> 1)) + byte
 *
 * For the first byte of Sector 0, the initial checksum value passed is 0.
 *
 * Returns updated 32-bit checksum value.
 */
static inline uint32_t
exfat_boot_checksum(const uint8_t *data, size_t size, uint32_t checksum)
{
	size_t i;

	for (i = 0; i < size; i++)
		checksum = ((checksum << 31) | (checksum >> 1)) + data[i];
	return (checksum);
}

/*
 * Accumulate 32-bit checksum for a single boot sector per Spec §3.4.
 * If is_sector0 is true, skips VolumeFlags (bytes 106-107) and PercentInUse
 * (byte 112).
 *
 * Returns updated 32-bit checksum value.
 */
static inline uint32_t
exfat_boot_sector_checksum(const uint8_t *sector, size_t sector_size,
    uint32_t checksum, bool is_sector0)
{
	size_t i;

	for (i = 0; i < sector_size; i++) {
		if (is_sector0 && (i == EXFAT_VOL_FLAGS_OFFSET ||
		    i == EXFAT_VOL_FLAGS_OFFSET + 1 ||
		    i == EXFAT_PERCENT_IN_USE_OFFSET))
			continue;
		checksum = ((checksum << 31) | (checksum >> 1)) + sector[i];
	}
	return (checksum);
}

/*
 * Calculate running 32-bit checksum across 11 boot sectors per Spec §3.4.
 *
 * Skips VolumeFlags (bytes 106-107) and PercentInUse (byte 112) of sector 0.
 *
 * Returns 32-bit accumulated checksum.
 */
static inline uint32_t
exfat_calc_boot_checksum(const uint8_t *sectors, size_t sector_size)
{
	uint32_t checksum;

	checksum = exfat_boot_sector_checksum(sectors, sector_size, 0, true);
	return (exfat_boot_checksum(sectors + sector_size,
	    sector_size * (EXFAT_BOOT_SECTORS_CHECKSUM - 1), checksum));
}

/*
 * Verify that Sector 11 is filled with repeating 32-bit checksum words.
 *
 * Returns true if every 32-bit word matches expected, false otherwise.
 */
static inline bool
exfat_verify_boot_checksum_sector(const uint8_t *sector11, size_t sector_size,
    uint32_t expected)
{
	size_t i, words;

	words = sector_size / sizeof(uint32_t);
	for (i = 0; i < words; i++)
		if (le32dec(sector11 + i * sizeof(uint32_t)) != expected)
			return (false);
	return (true);
}

/*
 * Populate Sector 11 with repeating 32-bit checksum words per Spec §3.4.
 */
static inline void
exfat_fill_boot_checksum_sector(uint8_t *sector11, size_t sector_size,
    uint32_t checksum)
{
	size_t i, words;

	words = sector_size / sizeof(uint32_t);
	for (i = 0; i < words; i++)
		le32enc(sector11 + i * sizeof(uint32_t), checksum);
}

/*
 * 16-bit rotate-and-add checksum for directory entry sets.
 *
 * Per exFAT Spec §6.3.3, computes the checksum across all 32-byte directory
 * entries that comprise a set (File Directory Entry, Stream Extension, and
 * File Name entries).  Bytes 2 and 3 of the primary File Directory Entry
 * (fe_set_checksum) are skipped during accumulation:
 *   checksum = ((checksum << 15) | (checksum >> 1)) + byte
 *
 * The caller initializes checksum to 0 before hashing the first entry.
 *
 * Returns updated 16-bit checksum value.
 */
static inline uint16_t
exfat_entry_checksum(const uint8_t *entry, uint16_t checksum,
    bool is_primary_file)
{
	size_t i;

	for (i = 0; i < EXFAT_DENTRY_SIZE; i++) {
		if (is_primary_file && (i == 2 || i == 3))
			continue;
		checksum = ((checksum << 15) | (checksum >> 1)) + entry[i];
	}
	return (checksum);
}

/*
 * Calculate directory entry set checksum per Spec §6.3.3.
 */
static inline uint16_t
exfat_dentry_calc_checksum(const union exfat_dentry *dentries, uint8_t count)
{
	uint16_t cs;

	cs = 0;
	for (uint8_t i = 0; i < count; i++)
		cs = exfat_entry_checksum(dentries[i].raw, cs, (i == 0));
	return (cs);
}

/*
 * Calculate and set the SetChecksum field of the primary directory entry.
 */
static inline void
exfat_dentry_set_checksum(union exfat_dentry *dentries, uint8_t count)
{
	uint16_t cs;

	cs = exfat_dentry_calc_checksum(dentries, count);
	dentries[0].file.fe_set_checksum = htole16(cs);
}

/*
 * 16-bit rotate-and-add hash for file and directory names.
 *
 * Per exFAT Spec §7.6.4, accumulates each UTF-16LE character of the
 * up-cased file name into a 16-bit hash (se_name_hash):
 *   hash = ((hash << 15) | (hash >> 1)) + (uint8_t)(ch & 0xFF)
 *   hash = ((hash << 15) | (hash >> 1)) + (uint8_t)(ch >> 8)
 *
 * The low byte is hashed first, followed by the high byte.
 * The caller initializes hash to 0 before processing the first character.
 *
 * Returns updated 16-bit name hash.
 */
static inline uint16_t
exfat_calc_name_hash(uint16_t upcase_char, uint16_t hash)
{
	hash = ((hash << 15) | (hash >> 1)) + (uint8_t)(upcase_char & 0xFF);
	hash = ((hash << 15) | (hash >> 1)) + (uint8_t)(upcase_char >> 8);
	return (hash);
}

/*
 * Cluster Heap Address Translation and Validation
 */

/*
 * Validate whether cluster number cn falls within valid cluster heap bounds
 * [EXFAT_FIRST_CLUSTER, EXFAT_FIRST_CLUSTER + cluster_count - 1] per
 * Spec §3.1.9.
 */
static inline bool
exfat_cluster_is_valid(uint32_t cn, uint32_t cluster_count)
{
	return (cn >= EXFAT_FIRST_CLUSTER && EXFAT_CNTOI(cn) < cluster_count);
}

/*
 * Convert cluster number cn to disk sector offset within Cluster Heap
 * per Spec §3.1.8.
 */
static inline uint64_t
exfat_cluster_to_sector(uint32_t heap_offset, uint8_t cluster_shift,
    uint32_t cn)
{
	return (heap_offset + ((uint64_t)EXFAT_CNTOI(cn) << cluster_shift));
}

#endif /* _FS_EXFAT_EXFAT_ONDISK_H_ */
