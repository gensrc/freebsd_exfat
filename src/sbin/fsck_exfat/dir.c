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
#include <sys/endian.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fs/exfat/exfat_unicode.h>

#include "fsck_exfat.h"
#include "fsutil.h"

#define MAX_DIR_DEPTH 256
#define MAX_ENTRY_SET 256

/*
 * Replace any EXFAT_ENTRY_EOD (0x00) markers in a directory cluster with
 * unused non-EOD entries (0x05) before advancing to or allocating a
 * subsequent cluster.  Per Spec §6.2.1, an EOD entry terminates the entire
 * directory; if a multi-slot entry set cannot fit in the trailing 1-2 slots
 * at the end of a cluster, leaving 0x00 in those trailing slots would
 * prematurely terminate directory traversal before the next cluster.
 *
 * Returns true if any EOD markers were replaced, false otherwise.
 */
static bool
clear_cluster_eod(union exfat_dentry *dent, size_t entries_per_cluster)
{
	bool changed = false;

	for (size_t k = 0; k < entries_per_cluster; k++) {
		if (dent[k].type == EXFAT_ENTRY_EOD || changed) {
			dent[k].type = EXFAT_ENTRY_FILE &
			    ~EXFAT_ENTRY_TYPE_IN_USE;
			changed = true;
		}
	}
	return (changed);
}

/*
 * Write an EXFAT_ENTRY_EOD (0x00) marker at slot 0 of next_cn when an EOD
 * marker at the end of the previous cluster was overwritten and next_cn is
 * already allocated in the directory's cluster chain.
 *
 * Per Spec §6.2.1, an EOD entry terminates the entire directory.  Preserving
 * EOD at the beginning of the next allocated cluster maintains the directory
 * termination invariant across cluster boundaries.
 */
static void
terminate_next_cluster(struct exfat_chk *chk, uint32_t next_cn, uint8_t *cbuf)
{
	union exfat_dentry *dent;

	if (!EXFAT_CLUSTER_VALID(chk, next_cn))
		return;
	if (read_cluster(chk, next_cn, cbuf) != 0)
		return;
	dent = (union exfat_dentry *)cbuf;
	dent[0].type = EXFAT_ENTRY_EOD;
	(void)write_cluster(chk, next_cn, cbuf);
}

/*
 * Insert a directory entry into the first available slot in the root directory.
 *
 * Traverses root directory clusters searching for an unused (InUse=0) or EOD
 * slot.  If an EOD slot is overwritten, preserves directory termination per
 * Spec §6.2.1 by placing a new EOD marker at the subsequent slot or next
 * cluster.
 *
 * Returns 0 on success, ENOSPC if no slot is available, or an I/O error.
 */
static int
insert_root_entry(struct exfat_chk *chk, const union exfat_dentry *entry)
{
	union exfat_dentry *dent;
	uint8_t *cbuf;
	size_t entries_per_cluster, k;
	uint32_t root_cn, walked = 0;
	bool slot_found = false;

	cbuf = malloc(chk->boot.cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	entries_per_cluster = chk->boot.cluster_size /
	    sizeof(union exfat_dentry);
	root_cn = chk->boot.root_dir_cluster;

	/*
	 * Phase 1: Search root directory clusters for an unused or EOD slot.
	 */
	while (EXFAT_CLUSTER_VALID(chk, root_cn)) {
		if (++walked > chk->boot.cluster_count)
			break;
		if (read_cluster(chk, root_cn, cbuf) != 0) {
			free(cbuf);
			return (EIO);
		}
		dent = (union exfat_dentry *)cbuf;

		for (k = 0; k < entries_per_cluster; k++) {
			uint8_t t = dent[k].type;

			if (t == EXFAT_ENTRY_EOD ||
			    (t & EXFAT_ENTRY_TYPE_IN_USE) == 0) {
				bool was_eod = (t == EXFAT_ENTRY_EOD);

				/*
				 * Phase 2: Overwrite slot and maintain EOD
				 * termination invariant (Spec §6.2.1).
				 */
				dent[k] = *entry;
				if (was_eod && k + 1 < entries_per_cluster)
					dent[k + 1].type = EXFAT_ENTRY_EOD;
				if (write_cluster(chk, root_cn, cbuf) != 0) {
					free(cbuf);
					return (EIO);
				}
				if (was_eod && k + 1 == entries_per_cluster) {
					uint32_t next_cn;

					if (fat_get(chk, root_cn, &next_cn) ==
					    0)
						terminate_next_cluster(chk,
						    next_cn, cbuf);
				}
				slot_found = true;
				break;
			}
		}
		if (slot_found)
			break;
		if (fat_get(chk, root_cn, &root_cn) != 0)
			break;
	}

	free(cbuf);
	return (slot_found ? 0 : ENOSPC);
}

/*
 * Locate and read the Volume Label entry (0x83) from the root directory.
 *
 * Searches root directory clusters for the Volume Label directory entry
 * (Spec §7.3) and converts the UTF-16 volume label to a null-terminated UTF-8
 * string in dst.  If no volume label entry is found, dst is set to an empty
 * string.
 *
 * Returns 0 on success, or an error code on failure.
 */
int
get_vol_label(struct exfat_chk *chk, char *dst, size_t dstlen)
{
	uint8_t *cbuf;
	uint32_t curr_cn, walked = 0;
	size_t entries_per_cluster;
	bool found = false;
	int error = 0;

	if (dstlen == 0)
		return (EINVAL);
	dst[0] = '\0';

	cbuf = malloc(chk->boot.cluster_size);
	if (cbuf == NULL) {
		perr("Out of memory allocating cluster buffer");
		return (ENOMEM);
	}

	entries_per_cluster = chk->boot.cluster_size /
	    sizeof(union exfat_dentry);
	curr_cn = chk->boot.root_dir_cluster;

	/*
	 * Phase 1: Root directory cluster traversal.
	 */
	while (EXFAT_CLUSTER_VALID(chk, curr_cn)) {
		union exfat_dentry *dent;
		size_t i;
		bool stop = false;

		if (++walked > chk->boot.cluster_count)
			break;
		error = read_cluster(chk, curr_cn, cbuf);
		if (error != 0) {
			perr("Failed reading root directory cluster %u",
			    curr_cn);
			break;
		}

		dent = (union exfat_dentry *)cbuf;
		for (i = 0; i < entries_per_cluster; i++) {
			uint8_t type = dent[i].type;

			if (type == EXFAT_ENTRY_EOD) {
				stop = true;
				break;
			}
			if ((type & EXFAT_ENTRY_TYPE_IN_USE) == 0)
				continue;

			/*
			 * Phase 2: Extract Volume Label entry (Spec §7.3) and
			 * convert UTF-16 to UTF-8.
			 */
			if (type == EXFAT_ENTRY_VOLUME_LABEL) {
				struct exfat_dentry_volume_label *vl;
				uint8_t nchars;

				vl = &dent[i].volume_label;
				nchars = vl->vl_character_count;
				if (nchars <= EXFAT_MAX_VOLUME_LABEL_CHARS) {
					uint16_t label_utf16[
					    EXFAT_MAX_VOLUME_LABEL_CHARS];

					for (uint8_t k = 0; k < nchars; k++)
						label_utf16[k] = le16toh(
						    vl->vl_volume_label[k]);
					exfat_utf16_to_utf8(label_utf16,
					    nchars, dst, dstlen);
					found = true;
				}
				stop = true;
				break;
			}
		}

		if (stop || found)
			break;

		if (fat_get(chk, curr_cn, &curr_cn) != 0)
			break;
	}

	free(cbuf);
	return (error);
}

/*
 * Create, update, or remove the Volume Label directory entry in the root.
 *
 * If label is empty or NULL, deletes the existing volume label entry.
 * Otherwise, validates label syntax, converts UTF-8 to UTF-16, and updates or
 * inserts the Volume Label entry (0x83) per Spec §7.3.
 *
 * Returns 0 on success, EINVAL on invalid characters, or an I/O error.
 */
int
set_vol_label(struct exfat_chk *chk, const char *label)
{
	uint8_t *cbuf;
	uint32_t curr_cn, found_cn = 0, walked = 0;
	size_t entries_per_cluster, found_idx = 0;
	uint16_t label_utf16[EXFAT_MAX_VOLUME_LABEL_CHARS];
	size_t nchars = 0, srclen;
	bool found = false;
	int error = 0;

	/*
	 * Phase 1: Input conversion and syntax validation (Spec §7.3).
	 */
	srclen = (label != NULL) ? strlen(label) : 0;
	if (srclen > 0) {
		error = exfat_utf8_to_utf16(label, srclen, label_utf16,
		    EXFAT_MAX_VOLUME_LABEL_CHARS, &nchars);
		if (error == ENAMETOOLONG) {
			perr("Volume label `%s' too long (max 11 characters)",
			    label);
			return (error);
		}
		if (error != 0) {
			perr("Volume label contains invalid UTF-8 sequence");
			return (error);
		}
		if (!exfat_is_valid_label(label_utf16, nchars)) {
			perr("Volume label contains invalid character");
			return (EINVAL);
		}
	}

	cbuf = malloc(chk->boot.cluster_size);
	if (cbuf == NULL) {
		perr("Out of memory allocating cluster buffer");
		return (ENOMEM);
	}

	entries_per_cluster = chk->boot.cluster_size /
	    sizeof(union exfat_dentry);
	curr_cn = chk->boot.root_dir_cluster;

	/*
	 * Phase 2: Root directory traversal to locate existing Volume Label.
	 */
	while (EXFAT_CLUSTER_VALID(chk, curr_cn)) {
		union exfat_dentry *dent;
		size_t i;
		bool stop = false;

		if (++walked > chk->boot.cluster_count)
			break;
		error = read_cluster(chk, curr_cn, cbuf);
		if (error != 0) {
			perr("Failed reading root directory cluster %u",
			    curr_cn);
			break;
		}

		dent = (union exfat_dentry *)cbuf;
		for (i = 0; i < entries_per_cluster; i++) {
			uint8_t type = dent[i].type;

			if (type == EXFAT_ENTRY_EOD) {
				stop = true;
				break;
			}
			if ((type & EXFAT_ENTRY_TYPE_IN_USE) == 0)
				continue;

			if (type == EXFAT_ENTRY_VOLUME_LABEL) {
				found = true;
				found_cn = curr_cn;
				found_idx = i;
				stop = true;
				break;
			}
		}

		if (stop || found)
			break;

		if (fat_get(chk, curr_cn, &curr_cn) != 0)
			break;
	}

	if (error != 0) {
		free(cbuf);
		return (error);
	}

	/*
	 * Phase 3: Create, update, or remove Volume Label directory entry.
	 */
	if (nchars > 0) {
		union exfat_dentry new_dent;

		memset(&new_dent, 0, sizeof(new_dent));
		new_dent.volume_label.vl_type = EXFAT_ENTRY_VOLUME_LABEL;
		new_dent.volume_label.vl_character_count = (uint8_t)nchars;
		for (size_t i = 0; i < nchars; i++)
			new_dent.volume_label.vl_volume_label[i] =
			    htole16(label_utf16[i]);

		if (found) {
			error = read_cluster(chk, found_cn, cbuf);
			if (error == 0) {
				union exfat_dentry *dent =
				    (union exfat_dentry *)cbuf;
				dent[found_idx] = new_dent;
				error = write_cluster(chk, found_cn, cbuf);
			}
		} else
			error = insert_root_entry(chk, &new_dent);
	} else if (found) {
		error = read_cluster(chk, found_cn, cbuf);
		if (error == 0) {
			union exfat_dentry *dent = (union exfat_dentry *)cbuf;
			dent[found_idx].type &= ~EXFAT_ENTRY_TYPE_IN_USE;
			error = write_cluster(chk, found_cn, cbuf);
		}
	}

	free(cbuf);
	return (error);
}

/*
 * Validate and process a Volume Label directory entry in the root directory
 * (Spec §7.3).
 *
 * Verifies that at most one Volume Label entry exists in the root directory
 * (Spec §7.3.1), enforces the 11-character limit (Spec §7.3.2), checks for
 * illegal characters (Spec §7.3.3), and repairs non-zero reserved bytes (Spec
 * §7.3).  Caches the validated label in chk->vol_label.
 *
 * Returns FSOK, FSDIRMOD on repair, FSERROR on uncorrected error, or FSFATAL.
 */
static int
check_root_volume_label(struct exfat_chk *chk, union exfat_dentry *dent,
    uint32_t curr_cn, uint8_t *cbuf, bool *found_vol_label)
{
	static const uint8_t zero_vl_res[8] = { 0 };
	struct exfat_dentry_volume_label *vl;
	uint16_t label_buf[EXFAT_MAX_VOLUME_LABEL_CHARS];
	int mod = FSOK;
	uint8_t nchars;

	vl = &dent->volume_label;
	nchars = vl->vl_character_count;

	/*
	 * Phase 1: Duplicate entry screening (Spec §7.3.1).
	 */
	if (*found_vol_label) {
		pwarn("Duplicate Volume Label entry in root directory\n");
		if (ask(1, "Remove duplicate Volume Label entry")) {
			dent->type &= ~EXFAT_ENTRY_TYPE_IN_USE;
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
		return (mod);
	}

	/*
	 * Phase 2: Character count validation (Spec §7.3.2).
	 */
	if (nchars > EXFAT_MAX_VOLUME_LABEL_CHARS) {
		pwarn("Invalid Volume Label character count %u (> 11) in root "
		    "directory\n", nchars);
		if (ask(1, "Remove invalid Volume Label entry")) {
			dent->type &= ~EXFAT_ENTRY_TYPE_IN_USE;
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
		return (mod);
	}

	/*
	 * Phase 3: Character validity screening (Spec §7.3.3).
	 */
	for (uint8_t k = 0; k < nchars; k++)
		label_buf[k] = le16toh(vl->vl_volume_label[k]);
	if (!exfat_is_valid_label(label_buf, nchars)) {
		pwarn("Invalid character in Volume Label entry in "
		    "root directory\n");
		if (ask(1, "Remove invalid Volume Label entry")) {
			dent->type &= ~EXFAT_ENTRY_TYPE_IN_USE;
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
		return (mod);
	}

	/*
	 * Phase 4: Reserved field validation and repair (Spec §7.3).
	 */
	if (memcmp(vl->vl_reserved, zero_vl_res, sizeof(zero_vl_res)) != 0) {
		pwarn("Non-zero reserved field in Volume Label "
		    "entry in root directory (Spec §7.3)\n");
		if (ask(1, "Fix Volume Label reserved field")) {
			memset(vl->vl_reserved, 0, sizeof(vl->vl_reserved));
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	/*
	 * Phase 5: Cache validated volume label into runtime state.
	 */
	exfat_utf16_to_utf8(label_buf, nchars, chk->vol_label,
	    sizeof(chk->vol_label));
	*found_vol_label = true;

	return (mod);
}

/*
 * Validate and process a Volume GUID directory entry in the root directory
 * (Spec §7.5).
 *
 * Verifies that at most one Volume GUID entry exists in the root directory
 * (Spec §7.5.1), checks that SecondaryCount and GeneralPrimaryFlags are zero
 * (Spec §7.5.2, §7.5.4), verifies the GUID is non-null (Spec §7.5.5), and
 * repairs non-zero reserved bytes (Spec §7.5).
 *
 * Returns FSOK, FSDIRMOD on repair, FSERROR on uncorrected error, or FSFATAL.
 */
static int
check_root_volume_guid(struct exfat_chk *chk, union exfat_dentry *dent,
    uint32_t curr_cn, uint8_t *cbuf, bool *found_vol_guid)
{
	static const uint8_t zero_guid[16] = { 0 };
	static const uint8_t zero_vg_res[10] = { 0 };
	struct exfat_dentry_volume_guid *vg;
	uint16_t act_csum, exp_csum;
	int mod = FSOK;

	vg = &dent->volume_guid;

	/*
	 * Phase 1: Duplicate entry screening (Spec §7.5.1).
	 */
	if (*found_vol_guid) {
		pwarn("Duplicate Volume GUID entry in root directory\n");
		if (ask(1, "Remove duplicate Volume GUID entry")) {
			dent->type &= ~EXFAT_ENTRY_TYPE_IN_USE;
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
		return (mod);
	}

	/*
	 * Phase 2: Secondary count and general flags validation (Spec §7.5.2,
	 * §7.5.4).
	 */
	if (vg->vg_secondary_count != 0 ||
	    le16toh(vg->vg_general_flags) != 0) {
		pwarn("Invalid secondary count %u or flags 0x%04x in "
		    "Volume GUID entry\n",
		    vg->vg_secondary_count,
		    le16toh(vg->vg_general_flags));
		if (ask(1, "Remove invalid Volume GUID entry")) {
			dent->type &= ~EXFAT_ENTRY_TYPE_IN_USE;
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
		return (mod);
	}

	/*
	 * Phase 3: Null GUID check (Spec §7.5.5).
	 */
	if (memcmp(vg->vg_guid, zero_guid, sizeof(zero_guid)) == 0) {
		pwarn("Null (all-zero) Volume GUID entry in root directory "
		    "(Spec §7.5.5)\n");
		if (ask(1, "Remove null Volume GUID entry")) {
			dent->type &= ~EXFAT_ENTRY_TYPE_IN_USE;
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
		return (mod);
	}

	/*
	 * Phase 4: Reserved field validation and repair (Spec §7.5).
	 */
	if (memcmp(vg->vg_reserved, zero_vg_res,
	    sizeof(zero_vg_res)) != 0) {
		pwarn("Non-zero reserved field in Volume GUID entry "
		    "in root directory (Spec §7.5)\n");
		if (ask(1, "Fix Volume GUID reserved field")) {
			memset(vg->vg_reserved, 0,
			    sizeof(vg->vg_reserved));
			exfat_dentry_set_checksum(dent, 1);
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	/*
	 * Phase 5: SetChecksum validation and repair (Spec §7.5.3, §6.3.3).
	 */
	exp_csum = exfat_dentry_calc_checksum(dent, 1);
	act_csum = le16toh(vg->vg_set_checksum);
	if (exp_csum != act_csum) {
		pwarn("Volume GUID entry checksum mismatch: 0x%04x != "
		    "0x%04x (Spec §7.5.3)\n", act_csum, exp_csum);
		if (ask(1, "Fix Volume GUID entry checksum")) {
			exfat_dentry_set_checksum(dent, 1);
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}
	*found_vol_guid = true;

	return (mod);
}

/*
 * Validate and repair a TexFAT Padding directory entry (Spec §7.10).
 *
 * TexFAT Padding entries are benign primary directory entries (Spec §7.10)
 * conforming to the generic primary directory entry template (Spec §6.3).
 * Verifies that SecondaryCount (Spec §6.3.2) and GeneralPrimaryFlags
 * (Spec §6.3.4) are zero and repairs non-zero reserved bytes (Spec §7.10).
 *
 * Returns FSOK, FSDIRMOD on repair, FSERROR on uncorrected error, or FSFATAL.
 */
static int
check_texfat_padding_entry(struct exfat_chk *chk, union exfat_dentry *dent,
    uint32_t curr_cn, uint8_t *cbuf, const char *path)
{
	static const uint8_t zero_tp_res[26] = { 0 };
	struct exfat_dentry_texfat_padding *tp;
	uint16_t act_csum, exp_csum;
	int mod = FSOK;

	tp = &dent->texfat_padding;

	/*
	 * Phase 1: Secondary count and general flags validation (Spec §6.3.2,
	 * §6.3.4).
	 */
	if (tp->tp_secondary_count != 0 ||
	    le16toh(tp->tp_general_flags) != 0) {
		if (path != NULL)
			pwarn("Invalid secondary count %u or flags 0x%04x in "
			    "TexFAT Padding entry in '%s'\n",
			    tp->tp_secondary_count,
			    le16toh(tp->tp_general_flags), path);
		else
			pwarn("Invalid secondary count %u or flags 0x%04x in "
			    "TexFAT Padding entry\n",
			    tp->tp_secondary_count,
			    le16toh(tp->tp_general_flags));
		if (ask(1, "Remove invalid TexFAT Padding entry")) {
			dent->type &= ~EXFAT_ENTRY_TYPE_IN_USE;
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
		return (mod);
	}

	/*
	 * Phase 2: Reserved field validation and repair (Spec §7.10).
	 */
	if (memcmp(tp->tp_reserved, zero_tp_res,
	    sizeof(zero_tp_res)) != 0) {
		if (path != NULL)
			pwarn("Non-zero reserved field in TexFAT Padding entry "
			    "in '%s' (Spec §7.10)\n", path);
		else
			pwarn("Non-zero reserved field in TexFAT Padding entry "
			    "in root directory (Spec §7.10)\n");
		if (ask(1, "Fix TexFAT Padding reserved field")) {
			memset(tp->tp_reserved, 0, sizeof(tp->tp_reserved));
			exfat_dentry_set_checksum(dent, 1);
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	/*
	 * Phase 3: SetChecksum validation and repair (Spec §7.10, §6.3.3).
	 */
	exp_csum = exfat_dentry_calc_checksum(dent, 1);
	act_csum = le16toh(tp->tp_set_checksum);
	if (exp_csum != act_csum) {
		if (path != NULL)
			pwarn("TexFAT Padding entry checksum mismatch in '%s': "
			    "0x%04x != 0x%04x (Spec §7.10)\n",
			    path, act_csum, exp_csum);
		else
			pwarn("TexFAT Padding entry checksum mismatch: "
			    "0x%04x != 0x%04x (Spec §7.10)\n",
			    act_csum, exp_csum);
		if (ask(1, "Fix TexFAT Padding entry checksum")) {
			exfat_dentry_set_checksum(dent, 1);
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	return (mod);
}

/*
 * Check whether target_cn belongs to the FAT cluster chain starting at
 * start_cn, bounded by cluster_count to guard against circular FAT loops.
 *
 * Returns true if target_cn is part of the chain, false otherwise.
 */
static bool
cluster_in_chain(struct exfat_chk *chk, uint32_t start_cn,
    uint32_t target_cn)
{
	uint32_t curr_cn, walked;

	curr_cn = start_cn;
	walked = 0;
	while (EXFAT_CLUSTER_VALID(chk, curr_cn)) {
		if (curr_cn == target_cn)
			return (true);
		if (++walked > chk->boot.cluster_count)
			break;
		if (fat_get(chk, curr_cn, &curr_cn) != 0)
			break;
	}
	return (false);
}

static const uint8_t syn_upcase[60] = {
	0xff, 0xff, 0x61, 0x00,
	0x41, 0x00, 0x42, 0x00, 0x43, 0x00,
	0x44, 0x00, 0x45, 0x00, 0x46, 0x00,
	0x47, 0x00, 0x48, 0x00, 0x49, 0x00,
	0x4a, 0x00, 0x4b, 0x00, 0x4c, 0x00,
	0x4d, 0x00, 0x4e, 0x00, 0x4f, 0x00,
	0x50, 0x00, 0x51, 0x00, 0x52, 0x00,
	0x53, 0x00, 0x54, 0x00, 0x55, 0x00,
	0x56, 0x00, 0x57, 0x00, 0x58, 0x00,
	0x59, 0x00, 0x5a, 0x00,
	0xff, 0xff, 0x85, 0xff
};
static const uint32_t syn_csum = 0x4e394ae1U;

/*
 * Free trailing clusters in a FAT chain starting after start_cn, clearing
 * allocated bits in both disk_bitmap and used_bitmap.
 */
static void
free_trailing_clusters(struct exfat_chk *chk, uint32_t start_cn)
{
	uint32_t next_cn, trail_cn;
	uint32_t walked = 0;

	if (fat_get(chk, start_cn, &trail_cn) != 0 ||
	    !EXFAT_CLUSTER_VALID(chk, trail_cn))
		return;

	while (EXFAT_CLUSTER_VALID(chk, trail_cn) &&
	    ++walked <= chk->boot.cluster_count) {
		uint32_t b_idx = EXFAT_CNTOI(trail_cn) / 8;
		uint8_t b_mask = 1U << (EXFAT_CNTOI(trail_cn) % 8);

		if (fat_get(chk, trail_cn, &next_cn) != 0 ||
		    EXFAT_FAT_IS_BAD(next_cn))
			break;
		fat_set(chk, trail_cn, EXFAT_FAT_FREE);
		if (chk->disk_bitmap != NULL)
			chk->disk_bitmap[b_idx] &= ~b_mask;
		if (chk->used_bitmap != NULL)
			chk->used_bitmap[b_idx] &= ~b_mask;
		trail_cn = next_cn;
	}
}

/*
 * Validate and record Allocation Bitmap entry in root directory (Spec §7.1).
 *
 * Verifies reserved fields, Second flag on single-FAT volumes, detects
 * duplicate bitmap entries, and records cluster/length for active and
 * secondary bitmaps.
 */
static int
check_root_bitmap_entry(struct exfat_chk *chk, union exfat_dentry *dent,
    uint32_t curr_cn, uint8_t *cbuf, bool active_fat_is_second,
    bool *found_bitmap0, bool *found_bitmap1, bool *found_bitmap)
{
	static const uint8_t zero_bm_res[18] = { 0 };
	uint8_t bm_mask;
	int mod = FSOK;
	bool bm_res_bad, is_second;

	bm_mask = (chk->boot.number_of_fats > 1) ?
	    EXFAT_BITMAP_FLAG_SECOND : 0;
	bm_res_bad = (dent->bitmap.bm_flags & ~bm_mask) != 0 ||
	    memcmp(dent->bitmap.bm_reserved, zero_bm_res,
	    sizeof(zero_bm_res)) != 0;
	if (bm_res_bad) {
		pwarn("Non-zero reserved fields in Allocation Bitmap entry "
		    "in root directory (Spec §7.1)\n");
		if (ask(1, "Fix Allocation Bitmap reserved fields")) {
			dent->bitmap.bm_flags &= bm_mask;
			memset(dent->bitmap.bm_reserved, 0,
			    sizeof(dent->bitmap.bm_reserved));
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	is_second = (dent->bitmap.bm_flags & EXFAT_BITMAP_FLAG_SECOND) != 0;
	if (chk->boot.number_of_fats == 1 && is_second) {
		pwarn("Allocation Bitmap has Second flag set on single-FAT "
		    "volume (Spec §7.1.2)\n");
		if (ask(1, "Clear Second flag in Allocation Bitmap")) {
			dent->bitmap.bm_flags &= ~EXFAT_BITMAP_FLAG_SECOND;
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
			is_second = false;
		} else {
			is_second = false;
			mod |= FSERROR;
		}
	}

	if ((is_second && *found_bitmap1) || (!is_second && *found_bitmap0)) {
		pwarn("Duplicate Allocation Bitmap entry in root directory\n");
		if (ask(1, "Remove duplicate Allocation Bitmap entry")) {
			dent->type &= ~EXFAT_ENTRY_TYPE_IN_USE;
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
		return (mod);
	}

	if (is_second)
		*found_bitmap1 = true;
	else
		*found_bitmap0 = true;

	/*
	 * Match bitmap to active FAT per Spec §3.1.13.1 & §7.1.2.
	 */
	if (is_second == active_fat_is_second) {
		if (!*found_bitmap) {
			chk->bitmap_cluster = le32toh(
			    dent->bitmap.bm_first_cluster);
			chk->bitmap_len = le64toh(
			    dent->bitmap.bm_data_length);
			*found_bitmap = true;
		}
	} else if (chk->boot.number_of_fats == 2) {
		chk->bitmap2_cluster = le32toh(
			dent->bitmap.bm_first_cluster);
		chk->bitmap2_len = le64toh(
			dent->bitmap.bm_data_length);
	}

	return (mod);
}

/*
 * Validate and record Up-case Table entry in root directory (Spec §7.2).
 *
 * Verifies reserved fields, detects duplicate Up-case Table entries, and
 * records cluster, length, checksum, and directory entry location.
 */
static int
check_root_upcase_entry(struct exfat_chk *chk, union exfat_dentry *dent,
    uint32_t curr_cn, size_t entry_idx, uint8_t *cbuf,
    uint32_t *upcase_entry_cn, size_t *upcase_entry_idx, bool *found_upcase)
{
	static const uint8_t zero_uc_res1[3] = { 0, 0, 0 };
	static const uint8_t zero_uc_res2[12] = { 0 };
	int mod = FSOK;
	bool uc_res_bad;

	if (*found_upcase) {
		pwarn("Duplicate Up-case Table entry in root directory\n");
		if (ask(1, "Remove duplicate Up-case Table entry")) {
			dent->type &= ~EXFAT_ENTRY_TYPE_IN_USE;
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
		return (mod);
	}

	uc_res_bad = memcmp(dent->upcase.uc_reserved1, zero_uc_res1,
	    sizeof(zero_uc_res1)) != 0 ||
	    memcmp(dent->upcase.uc_reserved2, zero_uc_res2,
	    sizeof(zero_uc_res2)) != 0;
	if (uc_res_bad) {
		pwarn("Non-zero reserved fields in Up-case Table entry in "
		    "root directory (Spec §7.2)\n");
		if (ask(1, "Fix Up-case Table reserved fields")) {
			memset(dent->upcase.uc_reserved1, 0,
			    sizeof(dent->upcase.uc_reserved1));
			memset(dent->upcase.uc_reserved2, 0,
			    sizeof(dent->upcase.uc_reserved2));
			if (write_cluster(chk, curr_cn, cbuf) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	chk->upcase_cluster = le32toh(dent->upcase.uc_first_cluster);
	chk->upcase_len = le64toh(dent->upcase.uc_data_length);
	chk->upcase_checksum = le32toh(dent->upcase.uc_table_checksum);
	*upcase_entry_cn = curr_cn;
	*upcase_entry_idx = entry_idx;
	*found_upcase = true;

	return (mod);
}

/*
 * Recreate missing Allocation Bitmap entry in root directory (Spec §7.1.3).
 *
 * Scans for a contiguous cluster run not colliding with the root directory
 * or Up-case Table, updates FAT entries with EOF termination, inserts a new
 * Allocation Bitmap directory entry, and initializes chk bitmap metadata.
 */
static int
synthesize_missing_bitmap(struct exfat_chk *chk, size_t min_bitmap_size,
    bool active_fat_is_second, bool found_upcase, bool *found_bitmap)
{
	union exfat_dentry bm_dent;
	uint8_t *cbuf;
	size_t bm_clusters;
	uint32_t bm_cn = 0, cand_cn;
	int mod = FSOK;

	pwarn("Allocation Bitmap entry missing in root directory\n");
	if (!ask(1, "Recreate missing Allocation Bitmap entry"))
		return (FSFATAL);

	bm_clusters = howmany(min_bitmap_size, chk->boot.cluster_size);
	for (cand_cn = EXFAT_FIRST_CLUSTER;
	    (uint64_t)EXFAT_CNTOI(cand_cn) + bm_clusters <=
	    chk->boot.cluster_count; cand_cn++) {
		bool clash = false;

		for (size_t bi = 0; bi < bm_clusters; bi++) {
			uint32_t c = cand_cn + (uint32_t)bi;
			uint32_t val;

			if ((fat_get(chk, c, &val) == 0 &&
			    EXFAT_FAT_IS_BAD(val)) ||
			    cluster_in_chain(chk, chk->boot.root_dir_cluster,
			    c) || (found_upcase &&
			    cluster_in_chain(chk, chk->upcase_cluster, c))) {
				clash = true;
				break;
			}
		}
		if (!clash) {
			bm_cn = cand_cn;
			break;
		}
	}

	if (bm_cn == 0)
		return (FSFATAL);

	cbuf = calloc(1, chk->boot.cluster_size);
	if (cbuf == NULL)
		return (FSFATAL);

	for (size_t bi = 0; bi < bm_clusters; bi++) {
		uint32_t c = bm_cn + (uint32_t)bi;
		uint32_t nxt;

		if (write_cluster(chk, c, cbuf) != 0) {
			free(cbuf);
			return (FSFATAL);
		}

		if (bi + 1 < bm_clusters) {
			if (fat_get(chk, c, &nxt) != 0 || nxt != c + 1) {
				fat_set(chk, c, c + 1);
				mod |= FSFATMOD;
			}
		} else {
			if (fat_get(chk, c, &nxt) != 0 ||
			    !EXFAT_FAT_IS_EOF(nxt)) {
				fat_set(chk, c, EXFAT_FAT_EOF);
				mod |= FSFATMOD;
			}
		}
	}
	free(cbuf);

	memset(&bm_dent, 0, sizeof(bm_dent));
	bm_dent.type = EXFAT_ENTRY_BITMAP;
	bm_dent.bitmap.bm_flags = active_fat_is_second ?
	    EXFAT_BITMAP_FLAG_SECOND : 0;
	bm_dent.bitmap.bm_first_cluster = htole32(bm_cn);
	bm_dent.bitmap.bm_data_length = htole64(min_bitmap_size);

	if (insert_root_entry(chk, &bm_dent) != 0)
		return (FSFATAL);

	chk->bitmap_cluster = bm_cn;
	chk->bitmap_len = min_bitmap_size;
	*found_bitmap = true;
	mod |= FSDIRMOD;

	return (mod);
}

/*
 * Recreate missing Up-case Table entry in root directory (Spec §7.2).
 *
 * Synthesizes default ASCII identity table or compressed synthetic table,
 * allocates clusters, updates disk_bitmap and used_bitmap, writes clusters,
 * and inserts a new Up-case Table directory entry into root directory.
 */
static int
synthesize_missing_upcase(struct exfat_chk *chk, size_t min_bitmap_size,
    bool *found_upcase)
{
	union exfat_dentry uc_dent;
	const uint8_t *raw_table;
	uint32_t cur, def_cn, uc_cn, uc_csum;
	size_t bm_clusters, rem, table_size, uc_clusters, write_len;
	off_t toff;
	int mod = FSOK;
	bool full_ok;

	pwarn("Up-Case Table entry missing in root directory\n");
	if (!ask(1, "Recreate missing Up-Case Table entry"))
		return (FSFATAL);

	table_size = EXFAT_UPCASE_TABLE_CHARS * sizeof(uint16_t);
	chk->upcase_table = malloc(table_size);
	if (chk->upcase_table == NULL)
		return (FSFATAL);

	for (uint32_t ch = 0; ch < EXFAT_UPCASE_TABLE_CHARS; ch++) {
		if (ch >= 'a' && ch <= 'z')
			chk->upcase_table[ch] = (uint16_t)(ch - 'a' + 'A');
		else
			chk->upcase_table[ch] = (uint16_t)ch;
	}

	bm_clusters = howmany(min_bitmap_size, chk->boot.cluster_size);
	uc_clusters = howmany(table_size, chk->boot.cluster_size);
	def_cn = EXFAT_ITOCN((uint32_t)bm_clusters);
	full_ok = ((uint64_t)EXFAT_CNTOI(def_cn) + uc_clusters <=
	    chk->boot.cluster_count);
	for (size_t ui = 0; full_ok && ui < uc_clusters; ui++) {
		uint32_t c = def_cn + (uint32_t)ui;

		if (is_cluster_used(chk, c) ||
		    cluster_in_chain(chk, chk->boot.root_dir_cluster, c))
			full_ok = false;
	}

	if (full_ok) {
		uc_cn = def_cn;
		raw_table = (const uint8_t *)chk->upcase_table;
		write_len = table_size;
		uc_csum = exfat_boot_checksum(raw_table, write_len, 0);
	} else {
		uc_cn = 0;
		if (EXFAT_CLUSTER_VALID(chk, def_cn) &&
		    !is_cluster_used(chk, def_cn) &&
		    !cluster_in_chain(chk, chk->boot.root_dir_cluster, def_cn))
			uc_cn = def_cn;
		for (uint32_t ci = 0; uc_cn == 0 &&
		    ci < chk->boot.cluster_count; ci++) {
			uint32_t c = EXFAT_ITOCN(ci);
			uint32_t idx = ci / 8;
			uint8_t mask = 1U << (ci % 8);

			if ((chk->disk_bitmap[idx] & mask) == 0 &&
			    !is_cluster_used(chk, c) &&
			    !cluster_in_chain(chk, chk->boot.root_dir_cluster,
			    c))
				uc_cn = c;
		}
		raw_table = syn_upcase;
		write_len = sizeof(syn_upcase);
		uc_csum = syn_csum;
	}

	if (uc_cn == 0)
		return (FSFATAL);

	rem = write_len;
	toff = 0;
	cur = uc_cn;
	while (rem > 0) {
		size_t wr = MIN(rem, chk->boot.cluster_size);
		uint8_t *tbuf = calloc(1, chk->boot.cluster_size);

		if (tbuf == NULL)
			return (FSFATAL);
		memcpy(tbuf, raw_table + toff, wr);
		write_cluster(chk, cur, tbuf);
		free(tbuf);
		mark_cluster_used(chk, cur, "up-case table");
		if (chk->disk_bitmap != NULL) {
			uint32_t b_idx = EXFAT_CNTOI(cur) / 8;
			uint8_t b_mask = 1U << (EXFAT_CNTOI(cur) % 8);

			chk->disk_bitmap[b_idx] |= b_mask;
		}
		rem -= wr;
		toff += wr;
		if (rem > 0) {
			fat_set(chk, cur, cur + 1);
			cur++;
		} else
			fat_set(chk, cur, EXFAT_FAT_EOF);
	}

	memset(&uc_dent, 0, sizeof(uc_dent));
	uc_dent.type = EXFAT_ENTRY_UPCASE;
	uc_dent.upcase.uc_table_checksum = htole32(uc_csum);
	uc_dent.upcase.uc_first_cluster = htole32(uc_cn);
	uc_dent.upcase.uc_data_length = htole64(write_len);

	if (insert_root_entry(chk, &uc_dent) != 0)
		return (FSFATAL);

	chk->upcase_cluster = uc_cn;
	chk->upcase_len = write_len;
	chk->upcase_checksum = uc_csum;
	*found_upcase = true;
	mod |= (FSDIRMOD | FSFATMOD);

	return (mod);
}

/*
 * Repair corrupt Up-case Table by synthesizing synthetic table (Spec §7.2).
 *
 * Writes syn_upcase table to disk, frees any trailing clusters, updates the
 * root directory Up-case entry, and initializes chk->upcase_table.
 */
static int
repair_corrupt_upcase_table(struct exfat_chk *chk, uint32_t upcase_entry_cn,
    size_t upcase_entry_idx)
{
	uint8_t *uc_buf;
	int mod = FSOK;

	pwarn("Corrupt or malformed Up-case table data (Spec §7.2)\n");
	if (!ask(1, "Synthesize default Up-case table")) {
		for (uint32_t c = 0; c < EXFAT_UPCASE_TABLE_CHARS; c++) {
			if (c >= 'a' && c <= 'z')
				chk->upcase_table[c] =
				    (uint16_t)(c - 'a' + 'A');
			else
				chk->upcase_table[c] = (uint16_t)c;
		}
		return (FSERROR);
	}

	uc_buf = calloc(1, chk->boot.cluster_size);
	if (uc_buf == NULL) {
		perr("Out of memory allocating cluster buffer");
		return (FSFATAL);
	}
	memcpy(uc_buf, syn_upcase, sizeof(syn_upcase));
	if (write_cluster(chk, chk->upcase_cluster, uc_buf) != 0) {
		free(uc_buf);
		return (FSFATAL);
	}
	free_trailing_clusters(chk, chk->upcase_cluster);
	fat_set(chk, chk->upcase_cluster, EXFAT_FAT_EOF);
	mod |= FSFATMOD;
	free(uc_buf);

	uc_buf = malloc(chk->boot.cluster_size);
	if (uc_buf == NULL) {
		perr("Out of memory allocating cluster buffer");
		return (FSFATAL);
	}
	if (read_cluster(chk, upcase_entry_cn, uc_buf) != 0) {
		free(uc_buf);
		return (FSFATAL);
	}
	union exfat_dentry *d = (union exfat_dentry *)uc_buf;

	d[upcase_entry_idx].upcase.uc_table_checksum = htole32(syn_csum);
	d[upcase_entry_idx].upcase.uc_data_length =
	    htole64(sizeof(syn_upcase));
	if (write_cluster(chk, upcase_entry_cn, uc_buf) != 0) {
		free(uc_buf);
		return (FSFATAL);
	}
	chk->upcase_checksum = syn_csum;
	chk->upcase_len = sizeof(syn_upcase);
	mod |= FSDIRMOD;
	free(uc_buf);

	(void)exfat_decompress_upcase(syn_upcase, sizeof(syn_upcase),
	    chk->upcase_table);

	return (mod);
}

/*
 * Locate and validate critical primary directory entries in the root directory.
 *
 * Searches for the Allocation Bitmap (0x81), Up-case Table (0x82), Volume
 * Label (0x83), Volume GUID (0xA0), and TexFAT Padding (0xA1) entries per
 * Spec §7.1 - §7.5 and §7.10.  Verifies table checksums, validates sizes,
 * loads tables into memory, tracks allocated metadata clusters in
 * used_bitmap, and synthesizes missing Allocation Bitmap or Up-case Table
 * entries if needed.
 *
 * Returns FSOK, FSDIRMOD, or FSFATAL if required metadata is missing or
 * unrecoverable.
 */
int
scan_root_metadata(struct exfat_chk *chk)
{
	uint8_t *cbuf, *raw_upcase;
	uint64_t walked;
	uint32_t curr_cn, csum, upcase_entry_cn = 0;
	bool active_fat_is_second;
	bool found_bitmap = false, found_upcase = false;
	bool found_bitmap0 = false, found_bitmap1 = false;
	bool found_vol_label = false, found_vol_guid = false;
	int error, mod;
	size_t entries_per_cluster, min_bitmap_size, remaining, offset;
	size_t upcase_entry_idx = 0;

	mod = FSOK;
	active_fat_is_second = (chk->boot.number_of_fats > 1) &&
	    ((chk->boot.volume_flags & EXFAT_VOL_ACTIVE_FAT) != 0);

	cbuf = malloc(chk->boot.cluster_size);
	if (cbuf == NULL) {
		perr("Out of memory allocating cluster buffer");
		return (FSFATAL);
	}

	entries_per_cluster = chk->boot.cluster_size /
	    sizeof(union exfat_dentry);
	curr_cn = chk->boot.root_dir_cluster;
	walked = 0;

	/*
	 * Phase 1: Root directory traversal and metadata discovery.
	 *
	 * Scan root directory clusters to locate critical volume metadata:
	 * Allocation Bitmap (Spec Section 7.1), Up-case Table (Spec Section
	 * 7.2), Volume Label (Spec Section 7.3), and Volume GUID (Spec
	 * Section 7.5). Validate uniqueness, character limits, and secondary
	 * entry counts.
	 */
	while (EXFAT_CLUSTER_VALID(chk, curr_cn)) {
		union exfat_dentry *dent;
		size_t i;
		bool stop = false;

		if (++walked > chk->boot.cluster_count) {
			pwarn("Cycle detected in root directory FAT chain\n");
			free(cbuf);
			return (FSFATAL);
		}

		error = read_cluster(chk, curr_cn, cbuf);
		if (error != 0) {
			free(cbuf);
			return (FSFATAL);
		}

		dent = (union exfat_dentry *)cbuf;
		for (i = 0; i < entries_per_cluster; i++) {
			uint8_t type = dent[i].type;

			if (type == EXFAT_ENTRY_EOD) {
				stop = true;
				break;
			}
			if ((type & EXFAT_ENTRY_TYPE_IN_USE) == 0)
				continue;

			if (type == EXFAT_ENTRY_BITMAP)
				mod |= check_root_bitmap_entry(chk, &dent[i],
				    curr_cn, cbuf, active_fat_is_second,
				    &found_bitmap0, &found_bitmap1,
				    &found_bitmap);
			else if (type == EXFAT_ENTRY_UPCASE)
				mod |= check_root_upcase_entry(chk, &dent[i],
				    curr_cn, i, cbuf, &upcase_entry_cn,
				    &upcase_entry_idx, &found_upcase);
			else if (type == EXFAT_ENTRY_VOLUME_LABEL)
				mod |= check_root_volume_label(chk, &dent[i],
				    curr_cn, cbuf, &found_vol_label);
			else if (type == EXFAT_ENTRY_VOLUME_GUID)
				mod |= check_root_volume_guid(chk, &dent[i],
				    curr_cn, cbuf, &found_vol_guid);
			else if (type == EXFAT_ENTRY_TEXFAT_PADDING)
				mod |= check_texfat_padding_entry(chk, &dent[i],
				    curr_cn, cbuf, NULL);
		}

		if (stop)
			break;

		error = fat_get(chk, curr_cn, &curr_cn);
		if (error != 0) {
			free(cbuf);
			return (FSFATAL);
		}
	}

	free(cbuf);

	/*
	 * Phase 2: Missing Allocation Bitmap validation and synthesis.
	 *
	 * Validate that the Allocation Bitmap entry was discovered in the root
	 * directory.  If absent, interactively recreate it per Spec §7.1,
	 * selecting a cluster range that does not collide with the root
	 * directory or Up-Case Table.
	 */
	min_bitmap_size = howmany((uint64_t)chk->boot.cluster_count, 8);
	if (!found_bitmap) {
		int ret;

		ret = synthesize_missing_bitmap(chk, min_bitmap_size,
		    active_fat_is_second, found_upcase, &found_bitmap);
		if ((ret & FSFATAL) != 0 || !found_bitmap)
			return (FSFATAL);
		mod |= ret;
	}

	/*
	 * Phase 3: Active Allocation Bitmap loading.
	 *
	 * Allocate buffer, traverse the bitmap's cluster chain with cycle
	 * detection, mark each cluster in used_bitmap, and read the bitmap
	 * into chk->disk_bitmap.
	 */
	if (chk->bitmap_len < min_bitmap_size ||
	    chk->bitmap_len > EXFAT_MAX_BITMAP_SIZE) {
		pwarn("Invalid allocation bitmap length (%ju bytes)\n",
		    (uintmax_t)chk->bitmap_len);
		return (FSFATAL);
	}

	chk->disk_bitmap = calloc(1, chk->bitmap_len);
	if (chk->disk_bitmap == NULL) {
		perr("Out of memory allocating disk bitmap buffer");
		return (FSFATAL);
	}

	curr_cn = chk->bitmap_cluster;
	remaining = chk->bitmap_len;
	offset = 0;
	walked = 0;
	cbuf = malloc(chk->boot.cluster_size);
	if (cbuf == NULL) {
		perr("Out of memory allocating cluster buffer");
		return (FSFATAL);
	}

	while (remaining > 0 && EXFAT_CLUSTER_VALID(chk, curr_cn)) {
		size_t to_copy = MIN(remaining, chk->boot.cluster_size);

		if (++walked > chk->boot.cluster_count ||
		    is_cluster_used(chk, curr_cn)) {
			pwarn(
			    "Cycle detected in allocation bitmap FAT chain\n");
			free(cbuf);
			return (FSFATAL);
		}
		mod |= mark_cluster_used(chk, curr_cn, "allocation bitmap");

		error = read_cluster(chk, curr_cn, cbuf);
		if (error != 0) {
			free(cbuf);
			return (FSFATAL);
		}
		memcpy(chk->disk_bitmap + offset, cbuf, to_copy);
		remaining -= to_copy;
		offset += to_copy;

		if (remaining > 0) {
			uint32_t next_cn;
			if (fat_get(chk, curr_cn, &next_cn) != 0)
				break;
			curr_cn = next_cn;
		}
	}
	if (remaining > 0) {
		pwarn("Allocation bitmap cluster chain truncated "
		    "(%zu bytes remaining)\n", remaining);
		free(cbuf);
		return (FSFATAL);
	}
	free(cbuf);

	/*
	 * If dual-FAT volume, traverse and mark secondary Allocation Bitmap
	 * in used_bitmap to prevent treating its clusters as orphans.
	 */
	if (chk->boot.number_of_fats == 2 && chk->bitmap2_cluster != 0) {
		uint32_t curr_cn2 = chk->bitmap2_cluster;
		uint64_t rem2 = chk->bitmap2_len;
		uint32_t walked2 = 0;

		if (chk->bitmap2_len < min_bitmap_size ||
		    chk->bitmap2_len > EXFAT_MAX_BITMAP_SIZE) {
			pwarn("Invalid secondary allocation bitmap length "
			    "(%ju bytes)\n", (uintmax_t)chk->bitmap2_len);
			return (FSFATAL);
		}

		while (rem2 > 0 && EXFAT_CLUSTER_VALID(chk, curr_cn2)) {
			size_t to_walk = MIN(rem2, chk->boot.cluster_size);

			if (++walked2 > chk->boot.cluster_count ||
			    is_cluster_used(chk, curr_cn2)) {
				pwarn("Cycle detected in secondary "
				    "allocation bitmap FAT chain\n");
				break;
			}
			mod |= mark_cluster_used(chk, curr_cn2,
			    "secondary allocation bitmap");
			rem2 -= to_walk;
			if (rem2 > 0) {
				uint32_t next_cn;

				if (fat_get(chk, curr_cn2, &next_cn) != 0)
					break;
				curr_cn2 = next_cn;
			}
		}
	} else if (chk->boot.number_of_fats == 2) {
		pwarn("Secondary Allocation Bitmap entry missing on dual-FAT "
		    "volume (Spec §7.1)\n");
		mod |= FSERROR;
	}

	/*
	 * Phase 4: Missing Up-case Table validation and synthesis.
	 *
	 * If no Up-case Table entry was found in Phase 1, attempt to
	 * synthesize a default identity table or compressed table on disk,
	 * allocate clusters, format an Up-case Table entry (Spec §7.2),
	 * and link into the root directory.
	 */
	if (!found_upcase) {
		int ret;

		ret = synthesize_missing_upcase(chk, min_bitmap_size,
		    &found_upcase);
		if ((ret & FSFATAL) != 0 || !found_upcase)
			return (FSFATAL);
		mod |= ret;
	}

	if (chk->upcase_table == NULL) {
		/*
		 * Phase 5: Active Up-case Table verification and decompression.
		 *
		 * Traverse the Up-case Table cluster chain, verify cluster
		 * validity, detect FAT cycles and cross-links via
		 * is_cluster_used(), validate the 32-bit table checksum
		 * (Spec §7.2.2), and decompress the table into the 128 KiB
		 * in-memory lookup table.
		 */
		if (!EXFAT_CLUSTER_VALID(chk, chk->upcase_cluster) ||
		    chk->upcase_len == 0 || (chk->upcase_len & 1) != 0 ||
		    chk->upcase_len > EXFAT_MAX_UPCASE_SIZE) {
			pwarn("Invalid up-case table cluster (%u) or "
			    "length (%ju bytes)\n", chk->upcase_cluster,
			    (uintmax_t)chk->upcase_len);
			return (FSFATAL);
		}

		raw_upcase = malloc(chk->upcase_len);
		if (raw_upcase == NULL) {
			perr("Out of memory allocating upcase buffer");
			return (FSFATAL);
		}

		curr_cn = chk->upcase_cluster;
		remaining = chk->upcase_len;
		offset = 0;
		walked = 0;
		cbuf = malloc(chk->boot.cluster_size);
		if (cbuf == NULL) {
			free(raw_upcase);
			perr("Out of memory allocating cluster buffer");
			return (FSFATAL);
		}

		while (remaining > 0 && EXFAT_CLUSTER_VALID(chk, curr_cn)) {
			size_t to_copy = MIN(remaining, chk->boot.cluster_size);

			if (++walked > chk->boot.cluster_count) {
				pwarn("Cycle detected in up-case table "
				    "FAT chain\n");
				free(raw_upcase);
				free(cbuf);
				return (FSFATAL);
			}
			if (is_cluster_used(chk, curr_cn)) {
				(void)mark_cluster_used(chk, curr_cn,
				    "up-case table");
				free(raw_upcase);
				free(cbuf);
				return (FSFATAL);
			}
			mod |= mark_cluster_used(chk, curr_cn,
			    "up-case table");

			error = read_cluster(chk, curr_cn, cbuf);
			if (error != 0) {
				free(raw_upcase);
				free(cbuf);
				return (FSFATAL);
			}
			memcpy(raw_upcase + offset, cbuf, to_copy);
			remaining -= to_copy;
			offset += to_copy;

			if (remaining > 0) {
				uint32_t next_cn;
				if (fat_get(chk, curr_cn, &next_cn) != 0)
					break;
				curr_cn = next_cn;
			}
		}
		free(cbuf);
		if (remaining > 0) {
			pwarn(
			    "Up-case table cluster chain truncated "
			    "(%zu bytes remaining)\n", remaining);
			free(raw_upcase);
			return (FSFATAL);
		}

		/* Verify Up-Case Checksum */
		csum = exfat_boot_checksum(raw_upcase, chk->upcase_len, 0);
		if (csum != chk->upcase_checksum) {
			pwarn("Up-case table checksum mismatch: computed "
			    "0x%08x != expected 0x%08x\n",
			    csum, chk->upcase_checksum);
			if (ask(1, "Fix Up-Case Table checksum")) {
				uint8_t *uc_buf =
				    malloc(chk->boot.cluster_size);

				if (uc_buf != NULL) {
					if (read_cluster(chk, upcase_entry_cn,
					    uc_buf) == 0) {
						union exfat_dentry *d =
						    (union exfat_dentry *)
						    uc_buf;

						d[upcase_entry_idx].upcase.
						    uc_table_checksum =
						    htole32(csum);
						if (write_cluster(chk,
						    upcase_entry_cn,
						    uc_buf) == 0) {
							chk->upcase_checksum =
							    csum;
							mod |= FSDIRMOD;
						} else
							mod |= FSFATAL;
					} else
						mod |= FSFATAL;
					free(uc_buf);
				} else {
					perr("Out of memory allocating "
					    "cluster buffer");
					mod |= FSFATAL;
				}
			} else
				mod |= FSERROR;
		}

		/* Decompress 128 KiB table */
		chk->upcase_table = malloc(EXFAT_UPCASE_TABLE_CHARS *
		    sizeof(uint16_t));
		if (chk->upcase_table == NULL) {
			perr("Out of memory allocating upcase table");
			free(raw_upcase);
			return (FSFATAL);
		}
		if (exfat_decompress_upcase(raw_upcase, chk->upcase_len,
		    chk->upcase_table) != 0) {
			int ret;

			ret = repair_corrupt_upcase_table(chk, upcase_entry_cn,
			    upcase_entry_idx);
			if ((ret & FSFATAL) != 0) {
				free(raw_upcase);
				return (FSFATAL);
			}
			mod |= ret;
		}
		free(raw_upcase);
	}

	/*
	 * Phase 6: Volume status reporting.
	 */
	if (verbose && chk->vol_label[0] != '\0')
		printf("Volume Label:  \"%s\"\n", chk->vol_label);

	return (mod);
}

/*
 * Count contiguous in-use secondary directory entries (0xC0..0xFF) in
 * set[1 .. sec_count].
 *
 * Per Spec §6.2.1.3 and §6.4.1.3, secondary entries have bit 6 set
 * (0xC0..0xFF when in-use).  Stops at the first non-secondary or unused
 * entry so removing or skipping a corrupted entry set does not inadvertently
 * delete or skip EOD (0x00) or subsequent valid primary directory entries.
 *
 * Returns the number of contiguous in-use secondary entries found.
 */
static uint8_t
count_secondary_entries(const union exfat_dentry *set, uint8_t sec_count)
{
	uint8_t s;

	for (s = 0; s < sec_count; s++) {
		uint8_t t = set[1 + s].type;

		if ((t & (EXFAT_ENTRY_TYPE_IN_USE |
		    EXFAT_ENTRY_TYPE_SECONDARY)) !=
		    (EXFAT_ENTRY_TYPE_IN_USE | EXFAT_ENTRY_TYPE_SECONDARY))
			break;
	}
	return (s);
}

/*
 * Mark all entries in a directory entry set as deleted on disk.
 *
 * Clears the InUse bit (bit 7) of each entry in the set, handling sets that
 * straddle cluster boundaries across both NoFatChain (contiguous) and
 * FAT-chained directory allocations.  Bounds secondary entry deletion to
 * contiguous secondary entries.
 *
 * Returns 0 on success, or an I/O error code.
 */
static int
delete_dentry_set(struct exfat_chk *chk, uint32_t curr_cn,
    union exfat_dentry *dent, size_t i, uint8_t sec_count, void *cbuf,
    size_t entries_per_cluster, bool no_fat_chain, uint64_t dir_size,
    size_t clusters_checked)
{
	size_t cur_avail, rem, s;
	uint32_t next_cn;
	uint8_t *next_cbuf;
	int error;

	/*
	 * Phase 1: Intra-cluster entry set deletion.
	 */
	if (i + 1 + sec_count <= entries_per_cluster) {
		dent[i].type &= ~EXFAT_ENTRY_TYPE_IN_USE;
		for (s = 1; s <= sec_count; s++) {
			if ((dent[i + s].type & (EXFAT_ENTRY_TYPE_IN_USE |
			    EXFAT_ENTRY_TYPE_SECONDARY)) !=
			    (EXFAT_ENTRY_TYPE_IN_USE |
			    EXFAT_ENTRY_TYPE_SECONDARY))
				break;
			dent[i + s].type &= ~EXFAT_ENTRY_TYPE_IN_USE;
		}
		return (write_cluster(chk, curr_cn, cbuf));
	}

	/*
	 * Phase 2: Straddled entry set deletion (current cluster portion).
	 */
	cur_avail = entries_per_cluster - i - 1;
	dent[i].type &= ~EXFAT_ENTRY_TYPE_IN_USE;
	for (s = 1; s <= cur_avail; s++) {
		if ((dent[i + s].type & (EXFAT_ENTRY_TYPE_IN_USE |
		    EXFAT_ENTRY_TYPE_SECONDARY)) !=
		    (EXFAT_ENTRY_TYPE_IN_USE | EXFAT_ENTRY_TYPE_SECONDARY))
			return (write_cluster(chk, curr_cn, cbuf));
		dent[i + s].type &= ~EXFAT_ENTRY_TYPE_IN_USE;
	}
	error = write_cluster(chk, curr_cn, cbuf);
	if (error != 0)
		return (error);

	/*
	 * Phase 3: Cross-cluster navigation and deletion across subsequent
	 * clusters.
	 */
	rem = sec_count - cur_avail;
	if (no_fat_chain) {
		if (dir_size > 0 &&
		    (clusters_checked + 1) * chk->boot.cluster_size >= dir_size)
			next_cn = EXFAT_FAT_EOF;
		else
			next_cn = curr_cn + 1;
	} else if (fat_get(chk, curr_cn, &next_cn) != 0)
		next_cn = EXFAT_FAT_EOF;

	while (rem > 0 && EXFAT_CLUSTER_VALID(chk, next_cn)) {
		size_t chunk = rem < entries_per_cluster ? rem :
		    entries_per_cluster;
		union exfat_dentry *next_dent;
		bool stop_del = false;

		next_cbuf = malloc(chk->boot.cluster_size);
		if (next_cbuf == NULL)
			return (ENOMEM);
		error = read_cluster(chk, next_cn, next_cbuf);
		if (error != 0) {
			free(next_cbuf);
			return (error);
		}
		next_dent = (union exfat_dentry *)next_cbuf;
		for (s = 0; s < chunk; s++) {
			if ((next_dent[s].type & (EXFAT_ENTRY_TYPE_IN_USE |
			    EXFAT_ENTRY_TYPE_SECONDARY)) !=
			    (EXFAT_ENTRY_TYPE_IN_USE |
			    EXFAT_ENTRY_TYPE_SECONDARY)) {
				stop_del = true;
				break;
			}
			next_dent[s].type &= ~EXFAT_ENTRY_TYPE_IN_USE;
		}
		error = write_cluster(chk, next_cn, next_cbuf);
		free(next_cbuf);
		if (error != 0 || stop_del)
			return (error);
		rem -= chunk;
		clusters_checked++;
		if (rem > 0) {
			if (no_fat_chain) {
				if (dir_size > 0 &&
				    (clusters_checked + 1) *
				    chk->boot.cluster_size >= dir_size)
					next_cn = EXFAT_FAT_EOF;
				else
					next_cn++;
			} else if (fat_get(chk, next_cn, &next_cn) != 0)
				next_cn = EXFAT_FAT_EOF;
		}
	}
	if (rem > 0)
		return (EIO);
	return (error);
}

/*
 * Write an updated directory entry set back to disk.
 *
 * Flushes primary and secondary entries, properly spanning across cluster
 * boundaries if the set straddles two clusters in either NoFatChain
 * (contiguous) or FAT-chained directory allocations.
 *
 * Returns 0 on success, or an I/O error code.
 */
static int
update_dentry_set(struct exfat_chk *chk, uint32_t curr_cn,
    union exfat_dentry *dent, size_t i, uint8_t sec_count,
    const union exfat_dentry *set, void *cbuf, size_t entries_per_cluster,
    bool no_fat_chain, uint64_t dir_size, size_t clusters_checked)
{
	size_t cur_avail, cur_pos, rem, s;
	uint32_t next_cn;
	uint8_t *next_cbuf;
	int error;

	/*
	 * Phase 1: Intra-cluster entry set flush.
	 */
	if (i + 1 + sec_count <= entries_per_cluster) {
		for (s = 0; s <= sec_count; s++)
			dent[i + s] = set[s];
		return (write_cluster(chk, curr_cn, cbuf));
	}

	/*
	 * Phase 2: Straddled entry set flush (current cluster portion).
	 */
	cur_avail = entries_per_cluster - i - 1;
	for (s = 0; s <= cur_avail; s++)
		dent[i + s] = set[s];
	error = write_cluster(chk, curr_cn, cbuf);
	if (error != 0)
		return (error);

	/*
	 * Phase 3: Cross-cluster navigation and writing across subsequent
	 * clusters.
	 */
	rem = sec_count - cur_avail;
	cur_pos = cur_avail + 1;
	if (no_fat_chain) {
		if (dir_size > 0 &&
		    (clusters_checked + 1) * chk->boot.cluster_size >= dir_size)
			next_cn = EXFAT_FAT_EOF;
		else
			next_cn = curr_cn + 1;
	} else if (fat_get(chk, curr_cn, &next_cn) != 0)
		next_cn = EXFAT_FAT_EOF;

	while (rem > 0 && EXFAT_CLUSTER_VALID(chk, next_cn)) {
		size_t chunk = rem < entries_per_cluster ? rem :
		    entries_per_cluster;
		union exfat_dentry *next_dent;

		next_cbuf = malloc(chk->boot.cluster_size);
		if (next_cbuf == NULL)
			return (ENOMEM);
		error = read_cluster(chk, next_cn, next_cbuf);
		if (error != 0) {
			free(next_cbuf);
			return (error);
		}
		next_dent = (union exfat_dentry *)next_cbuf;
		for (s = 0; s < chunk; s++)
			next_dent[s] = set[cur_pos + s];
		error = write_cluster(chk, next_cn, next_cbuf);
		free(next_cbuf);
		if (error != 0)
			return (error);
		cur_pos += chunk;
		rem -= chunk;
		clusters_checked++;
		if (rem > 0) {
			if (no_fat_chain) {
				if (dir_size > 0 &&
				    (clusters_checked + 1) *
				    chk->boot.cluster_size >= dir_size)
					next_cn = EXFAT_FAT_EOF;
				else
					next_cn++;
			} else if (fat_get(chk, next_cn, &next_cn) != 0)
				next_cn = EXFAT_FAT_EOF;
		}
	}
	if (rem > 0)
		return (EIO);
	return (error);
}

/*
 * Truncate a file stream's directory entry set at cluster index c_idx.
 *
 * Updates DataLength, ValidDataLength, clears NoFatChain if truncating to zero,
 * recalculates SetChecksum per Spec §7.4.3, and writes the updated dentry set.
 */
static int
truncate_file_stream(struct exfat_chk *chk, struct exfat_dentry_stream *se,
    union exfat_dentry *dent, union exfat_dentry *set, size_t d_idx,
    uint8_t sec_count, void *cbuf, size_t entries_per_cluster,
    bool dir_no_fat_chain, uint64_t dir_size, size_t clusters_checked,
    uint32_t curr_cn, uint64_t c_idx)
{
	uint64_t data_len, valid_len;

	if (c_idx == 0) {
		se->se_first_cluster = 0;
		se->se_data_length = 0;
		se->se_valid_data_length = 0;
		se->se_general_flags &= ~EXFAT_FLAG_NO_FAT_CHAIN;
	} else {
		data_len = c_idx * chk->boot.cluster_size;
		valid_len = le64toh(se->se_valid_data_length);
		if (valid_len > data_len)
			valid_len = data_len;
		se->se_data_length = htole64(data_len);
		se->se_valid_data_length = htole64(valid_len);
	}
	exfat_dentry_set_checksum(set, 1 + sec_count);
	if (update_dentry_set(chk, curr_cn, dent, d_idx, sec_count, set, cbuf,
	    entries_per_cluster, dir_no_fat_chain, dir_size,
	    clusters_checked) == 0)
		return (FSDIRMOD);
	return (FSFATAL);
}

/*
 * Validate cluster allocation chain for a file or directory data stream.
 *
 * Verifies cluster heap boundaries, validates NoFatChain consistency (Spec
 * §7.6.2 / §6.4.2), detects FAT cycles, cross-linked clusters, and bad
 * clusters.  Prompts user to truncate or repair invalid chains, drop
 * superfluous clusters, or free unallocated allocations.
 *
 * Returns FSOK, FSDIRMOD, FSFATMOD, or FSERROR.
 */
static int
check_file_clusters(struct exfat_chk *chk, const char *full_path,
    struct exfat_dentry_stream *se, union exfat_dentry *dent,
    union exfat_dentry *set, size_t d_idx, uint8_t sec_count, void *cbuf,
    size_t entries_per_cluster, bool dir_no_fat_chain, uint64_t dir_size,
    size_t clusters_checked, uint32_t curr_cn)
{
	uint64_t c_idx, data_len, needed_clusters;
	uint32_t first_cn, first_val;
	int mod;
	bool file_no_fat_chain;

	mod = FSOK;
	data_len = le64toh(se->se_data_length);
	first_cn = le32toh(se->se_first_cluster);
	file_no_fat_chain = (se->se_general_flags &
	    EXFAT_FLAG_NO_FAT_CHAIN) != 0;

	/*
	 * Phase 1: Boundary validation and empty file sanitization.
	 *
	 * Detect files with zero DataLength allocating clusters or starting
	 * at bad clusters, offering interactive repair and SetChecksum update.
	 */
	if (data_len == 0) {
		if (EXFAT_CLUSTER_VALID(chk, first_cn)) {
			pwarn("File '%s' has zero length but "
			    "allocates cluster %u\n", full_path, first_cn);
			if (ask(1, "Drop superfluous clusters")) {
				if (!file_no_fat_chain) {
					uint32_t next_scn, scn;
					uint32_t walked = 0;

					scn = first_cn;
					while (EXFAT_CLUSTER_VALID(chk, scn) &&
					    !is_cluster_used(chk, scn) &&
					    ++walked <=
					    chk->boot.cluster_count) {
						uint32_t b_idx =
						    EXFAT_CNTOI(scn) / 8;
						uint8_t b_mask = 1U <<
						    (EXFAT_CNTOI(scn) % 8);

						if (fat_get(chk, scn,
						    &next_scn) != 0 ||
						    EXFAT_FAT_IS_BAD(next_scn))
							break;
						fat_set(chk, scn,
						    EXFAT_FAT_FREE);
						if (chk->disk_bitmap != NULL)
							chk->disk_bitmap[b_idx]
							    &= ~b_mask;
						scn = next_scn;
					}
				} else if (!is_cluster_used(chk, first_cn) &&
				    chk->disk_bitmap != NULL) {
					uint32_t b_idx =
					    EXFAT_CNTOI(first_cn) / 8;
					uint8_t b_mask = 1U <<
					    (EXFAT_CNTOI(first_cn) % 8);

					chk->disk_bitmap[b_idx] &= ~b_mask;
				}
				mod |= truncate_file_stream(chk, se, dent, set,
				    d_idx, sec_count, cbuf, entries_per_cluster,
				    dir_no_fat_chain, dir_size,
				    clusters_checked, curr_cn, 0);
				if ((mod & FSDIRMOD) != 0)
					mod |= FSFATMOD;
			} else
				mod |= FSERROR;
		}
		return (mod);
	}

	if (!EXFAT_CLUSTER_VALID(chk, first_cn)) {
		pwarn("File '%s' starts with invalid cluster %u\n",
		    full_path, first_cn);
		if (ask(0, "Truncate file with invalid starting cluster")) {
			mod |= truncate_file_stream(chk, se, dent, set, d_idx,
			    sec_count, cbuf, entries_per_cluster,
			    dir_no_fat_chain, dir_size, clusters_checked,
			    curr_cn, 0);
			return (mod);
		}
		mod |= FSERROR;
		return (mod);
	}

	if (fat_get(chk, first_cn, &first_val) == 0 &&
	    EXFAT_FAT_IS_BAD(first_val)) {
		pwarn("File '%s' starts with bad cluster\n", full_path);
		if (ask(0, "Truncate file at bad cluster")) {
			mod |= truncate_file_stream(chk, se, dent, set, d_idx,
			    sec_count, cbuf, entries_per_cluster,
			    dir_no_fat_chain, dir_size, clusters_checked,
			    curr_cn, 0);
			return (mod);
		}
		mod |= FSERROR;
		return (mod);
	}

	needed_clusters = (data_len / chk->boot.cluster_size) +
	    ((data_len % chk->boot.cluster_size) != 0);

	if (file_no_fat_chain) {
		/*
		 * Phase 2-1: Contiguous stream validation (Spec Section
		 * 7.6.2 / 6.4.2 NoFatChain flag set).
		 *
		 * Subphase 2-1a: Verify cluster heap boundaries and truncate
		 * if the stream extends past the end of the cluster heap.
		 */
		if (needed_clusters > chk->boot.cluster_count ||
		    (uint64_t)EXFAT_CNTOI(first_cn) +
		    needed_clusters > chk->boot.cluster_count) {
			pwarn("Contiguous file '%s' extends beyond "
			    "cluster heap\n", full_path);
			if (ask(0, "Truncate file to cluster heap boundary")) {
				uint64_t avail_clusters;

				if (EXFAT_CNTOI(first_cn) <
				    chk->boot.cluster_count)
					avail_clusters =
					    chk->boot.cluster_count -
					    EXFAT_CNTOI(first_cn);
				else
					avail_clusters = 0;

				mod |= truncate_file_stream(chk, se, dent, set,
				    d_idx, sec_count, cbuf, entries_per_cluster,
				    dir_no_fat_chain, dir_size,
				    clusters_checked, curr_cn, avail_clusters);
				needed_clusters = avail_clusters;
				if (needed_clusters == 0)
					return (mod);
			} else {
				mod |= FSERROR;
				return (mod);
			}
		}
		/*
		 * Subphase 2-1b: Iterate contiguous clusters, detecting
		 * cross-links via is_cluster_used(), checking for bad FAT
		 * entries, and recording allocated clusters in used_bitmap.
		 */
		for (c_idx = 0; c_idx < needed_clusters; c_idx++) {
			uint32_t cn, fat_val;

			cn = first_cn + c_idx;
			if (is_cluster_used(chk, cn)) {
				uint32_t b_idx = EXFAT_CNTOI(cn) / 8;
				uint8_t b_mask = 1U << (EXFAT_CNTOI(cn) % 8);

				pwarn("Cluster %u cross-linked in '%s'\n",
				    cn, full_path);
				if (ask(0, "Truncate file at cross-link")) {
					mod |= truncate_file_stream(chk, se,
					    dent, set, d_idx, sec_count, cbuf,
					    entries_per_cluster,
					    dir_no_fat_chain, dir_size,
					    clusters_checked, curr_cn, c_idx);
					break;
				}
				chk->dup_bitmap[b_idx] |= b_mask;
				mod |= FSERROR;
				continue;
			}

			if (fat_get(chk, cn, &fat_val) == 0 &&
			    EXFAT_FAT_IS_BAD(fat_val)) {
				pwarn("File '%s' cluster %u is marked bad\n",
				    full_path, cn);
				if (ask(0, "Truncate file at bad cluster")) {
					mod |= truncate_file_stream(chk, se,
					    dent, set, d_idx, sec_count, cbuf,
					    entries_per_cluster,
					    dir_no_fat_chain, dir_size,
					    clusters_checked, curr_cn, c_idx);
					break;
				}
				mod |= FSERROR;
				continue;
			}

			mod |= mark_cluster_used(chk, cn, full_path);
		}
	} else {
		/*
		 * Phase 2-2: FAT-chained stream validation (Spec Section
		 * 7.6.2 / 6.4.2 NoFatChain flag cleared).
		 *
		 * Subphase 2-2a: Traverse the FAT chain, detecting cycles,
		 * cross-links via is_cluster_used(), and bad cluster entries,
		 * while marking allocated clusters in used_bitmap.
		 */
		uint32_t last_valid_cn, next_scn, prev_scn, scn;

		last_valid_cn = 0;
		prev_scn = 0;
		scn = first_cn;
		c_idx = 0;

		while (EXFAT_CLUSTER_VALID(chk, scn)) {
			if (is_cluster_used(chk, scn)) {
				uint32_t b_idx = EXFAT_CNTOI(scn) / 8;
				uint8_t b_mask = 1U << (EXFAT_CNTOI(scn) % 8);

				if (c_idx >= needed_clusters) {
					c_idx++;
					break;
				}
				pwarn("Cluster %u cross-linked in '%s'\n",
				    scn, full_path);
				if (ask(0, "Truncate file at cross-link")) {
					if (c_idx > 0)
						fat_set(chk, prev_scn,
						    EXFAT_FAT_EOF);
					mod |= truncate_file_stream(chk, se,
					    dent, set, d_idx, sec_count, cbuf,
					    entries_per_cluster,
					    dir_no_fat_chain, dir_size,
					    clusters_checked, curr_cn, c_idx);
					if (c_idx > 0 && (mod & FSDIRMOD) != 0)
						mod |= FSFATMOD;
					needed_clusters = c_idx;
					break;
				}
				chk->dup_bitmap[b_idx] |= b_mask;
				mod |= FSERROR;
				needed_clusters = c_idx;
				break;
			}

			if (fat_get(chk, scn, &next_scn) != 0) {
				mod |= FSERROR;
				break;
			}

			if (EXFAT_FAT_IS_BAD(next_scn)) {
				pwarn("File '%s' cluster %u is marked bad\n",
				    full_path, scn);
				if (ask(0, "Truncate file at bad cluster")) {
					if (c_idx > 0)
						fat_set(chk, prev_scn,
						    EXFAT_FAT_EOF);
					mod |= truncate_file_stream(chk, se,
					    dent, set, d_idx, sec_count, cbuf,
					    entries_per_cluster,
					    dir_no_fat_chain, dir_size,
					    clusters_checked, curr_cn, c_idx);
					if (c_idx > 0 && (mod & FSDIRMOD) != 0)
						mod |= FSFATMOD;
					needed_clusters = c_idx;
					break;
				}
				mod |= FSERROR;
				needed_clusters = c_idx;
				break;
			}

			if (c_idx < needed_clusters) {
				mod |= mark_cluster_used(chk, scn, full_path);
				last_valid_cn = scn;
			}
			c_idx++;

			if (c_idx > chk->boot.cluster_count) {
				pwarn("Cycle detected in FAT chain of '%s'\n",
				    full_path);
				mod |= FSERROR;
				break;
			}
			prev_scn = scn;
			scn = next_scn;
		}

		/*
		 * Subphase 2-2b: Reconcile chain length — handle truncated
		 * FAT chain where fewer clusters were found than required by
		 * DataLength (c_idx < needed_clusters).
		 */
		if (c_idx < needed_clusters) {
			pwarn("File '%s' FAT chain has %ju clusters, "
			    "expected %ju\n", full_path, c_idx,
			    needed_clusters);
			if (ask(0,
			    "Truncate file to allocated cluster chain")) {
				if (c_idx > 0 && last_valid_cn != 0)
					fat_set(chk, last_valid_cn,
					    EXFAT_FAT_EOF);
				mod |= truncate_file_stream(chk, se, dent,
				    set, d_idx, sec_count, cbuf,
				    entries_per_cluster, dir_no_fat_chain,
				    dir_size, clusters_checked, curr_cn,
				    c_idx);
				if (c_idx > 0 && (mod & FSDIRMOD) != 0)
					mod |= FSFATMOD;
			} else
				mod |= FSERROR;
		} else if (c_idx > needed_clusters) {
			/*
			 * Subphase 2-2c: Reconcile chain length — handle
			 * superfluous clusters where more clusters were
			 * found than required by DataLength.
			 */
			pwarn("File '%s' has %ju superfluous clusters "
			    "(%ju > %ju)\n", full_path,
			    c_idx - needed_clusters, c_idx, needed_clusters);
			if (ask(1, "Drop superfluous clusters")) {
				uint32_t cur = last_valid_cn;
				uint32_t nxt;
				uint32_t walked = 0;

				if (fat_get(chk, cur, &nxt) == 0) {
					fat_set(chk, cur, EXFAT_FAT_EOF);
					cur = nxt;
					while (EXFAT_CLUSTER_VALID(chk, cur) &&
					    !is_cluster_used(chk, cur) &&
					    ++walked <=
					    chk->boot.cluster_count) {
						uint32_t b_idx =
						    EXFAT_CNTOI(cur) / 8;
						uint8_t b_mask = 1U <<
						    (EXFAT_CNTOI(cur) % 8);

						if (fat_get(chk, cur, &nxt)
						    != 0 ||
						    EXFAT_FAT_IS_BAD(nxt))
							break;
						fat_set(chk, cur,
						    EXFAT_FAT_FREE);
						if (chk->disk_bitmap != NULL)
							chk->disk_bitmap[b_idx]
							    &= ~b_mask;
						cur = nxt;
					}
					mod |= FSFATMOD;
				}
			} else {
				uint32_t cur, nxt, sup_count;

				cur = last_valid_cn;
				sup_count = 0;
				while (fat_get(chk, cur, &nxt) == 0 &&
				    EXFAT_CLUSTER_VALID(chk, nxt)) {
					if (is_cluster_used(chk, nxt) ||
					    ++sup_count >
					    chk->boot.cluster_count)
						break;
					mod |= mark_cluster_used(chk, nxt,
					    full_path);
					cur = nxt;
				}
				mod |= FSERROR;
			}
		}
	}

	return (mod);
}

/*
 * Read trailing secondary directory entries that cross a cluster boundary.
 *
 * Follows the directory's cluster chain (supporting both NoFatChain
 * contiguous allocations bounded by dir_size and FAT-chained traversal)
 * to load the remaining entries of a multi-slot entry set into the caller's
 * set buffer.
 */
static void
read_straddled_entries(struct exfat_chk *chk, uint32_t next_cn,
    union exfat_dentry *set, size_t cur_avail, uint8_t sec_count,
    bool no_fat_chain, uint64_t dir_size, size_t clusters_checked)
{
	uint8_t *next_cbuf;
	size_t cur_pos, entries_per_cluster, rem, s;

	entries_per_cluster = chk->boot.cluster_size /
	    sizeof(union exfat_dentry);
	cur_pos = cur_avail + 1;
	rem = sec_count - cur_avail;

	/*
	 * Phase 1: Read remaining secondary entries across subsequent
	 * clusters.
	 */
	while (rem > 0 && EXFAT_CLUSTER_VALID(chk, next_cn)) {
		size_t chunk = rem < entries_per_cluster ? rem :
		    entries_per_cluster;
		union exfat_dentry *next_dent;

		next_cbuf = malloc(chk->boot.cluster_size);
		if (next_cbuf == NULL)
			break;
		if (read_cluster(chk, next_cn, next_cbuf) != 0) {
			free(next_cbuf);
			break;
		}
		next_dent = (union exfat_dentry *)next_cbuf;
		for (s = 0; s < chunk; s++)
			set[cur_pos + s] = next_dent[s];
		free(next_cbuf);
		cur_pos += chunk;
		rem -= chunk;
		clusters_checked++;
		if (rem > 0) {
			if (no_fat_chain) {
				if (dir_size > 0 &&
				    (clusters_checked + 1) *
				    chk->boot.cluster_size >= dir_size)
					next_cn = EXFAT_FAT_EOF;
				else
					next_cn++;
			} else if (fat_get(chk, next_cn, &next_cn) != 0)
				next_cn = EXFAT_FAT_EOF;
		}
	}

	/*
	 * Phase 2: Zero any unread trailing slots on premature EOF or error.
	 */
	for (; cur_pos <= sec_count; cur_pos++)
		memset(&set[cur_pos], 0, sizeof(set[cur_pos]));
}

/*
 * Validate UTC offset field per Spec §7.4.10.
 *
 * When OffsetValid (bit 7) is 0, the remainder of the field shall be 0.
 * When OffsetValid is 1, bits 0-6 form a 7-bit two's complement integer
 * representing the offset in 15-minute intervals between -56 (-14:00) and
 * +56 (+14:00).
 *
 * Returns true if valid, false otherwise.
 */
static inline bool
exfat_is_valid_utc_offset(uint8_t val)
{
	int8_t off;

	if ((val & 0x80) == 0)
		return (val == 0);

	if (val & 0x40)
		off = (int8_t)((val & 0x7F) | 0x80);
	else
		off = (int8_t)(val & 0x3F);

	return (off >= -56 && off <= 56);
}

/*
 * Validate MS-DOS 32-bit date and time format per Spec §7.4.8.
 *
 * Verifies DoubleSeconds (bits 0-4, range 0-29), Minute (bits 5-10, range
 * 0-59), Hour (bits 11-15, range 0-23), Day (bits 16-20, range 1-31),
 * Month (bits 21-24, range 1-12), and Year (bits 25-31, offset from 1980).
 * A timestamp of 0 represents unset/epoch.
 *
 * Returns true if valid, false otherwise.
 */
static inline bool
exfat_is_valid_timestamp(uint32_t ts)
{
	uint32_t day, hour, min, month, sec2;

	if (ts == 0)
		return (true);

	sec2 = ts & 0x1F;
	min = (ts >> 5) & 0x3F;
	hour = (ts >> 11) & 0x1F;
	day = (ts >> 16) & 0x1F;
	month = (ts >> 21) & 0x0F;

	return (sec2 <= 29 && min <= 59 && hour <= 23 &&
	    day >= 1 && day <= 31 && month >= 1 && month <= 12);
}

/*
 * Validate and repair secondary directory entry flags in a file directory set
 * (Spec §7.4 - §7.9).
 *
 * Verifies File Name entry general flags (must be 0 per Spec §7.7.2), enforces
 * benign vs critical secondary entry type requirements (Spec §6.4.1.2,
 * §7.4.2), checks Vendor Extension flags (Spec §7.8.2), and validates Vendor
 * Allocation flags (Spec §7.9.2).  Prompts user to fix corrupted flags and
 * updates SetChecksum.
 *
 * Returns FSOK, FSDIRMOD on repair, FSERROR on uncorrected error, or FSFATAL.
 */
static int
check_file_secondary_flags(struct exfat_chk *chk, uint32_t curr_cn,
    union exfat_dentry *dent, size_t i, size_t sec_count,
    size_t num_name_entries, union exfat_dentry *set, uint8_t *cbuf,
    size_t entries_per_cluster, bool no_fat_chain, uint64_t dir_size,
    uint32_t clusters_checked, const char *path, bool *bad_secondary)
{
	size_t s;
	int mod = FSOK;
	bool name_flags_bad = false, vendor_flags_bad = false;

	/*
	 * Phase 1: Secondary entry screening (File Name entries vs
	 * benign/vendor secondary entries).
	 */
	for (s = 2; s <= sec_count; s++) {
		if (s <= 1 + num_name_entries) {
			if (set[s].type != EXFAT_ENTRY_NAME) {
				pwarn("Expected File Name entry (0xC1) in "
				    "'%s', found 0x%02x\n", path, set[s].type);
				*bad_secondary = true;
				break;
			}
			if (set[s].name.ne_general_flags != 0) {
				pwarn("Invalid flags (0x%02x) in File Name "
				    "entry in '%s'\n",
				    set[s].name.ne_general_flags, path);
				name_flags_bad = true;
			}
		} else {
			if ((set[s].type &
			    (EXFAT_ENTRY_TYPE_IN_USE |
			    EXFAT_ENTRY_TYPE_SECONDARY |
			    EXFAT_ENTRY_TYPE_BENIGN)) !=
			    (EXFAT_ENTRY_TYPE_IN_USE |
			    EXFAT_ENTRY_TYPE_SECONDARY |
			    EXFAT_ENTRY_TYPE_BENIGN)) {
				/* Spec §6.4.1.2 and §7.4.2. */
				pwarn("Invalid secondary (0x%02x) in '%s'\n",
				    set[s].type, path);
				*bad_secondary = true;
				break;
			}
			if (set[s].type == EXFAT_ENTRY_VENDOR_EXT &&
			    set[s].vendor_ext.ve_general_flags != 0) {
				pwarn("Invalid flags (0x%02x) in Vendor "
				    "Extension entry in '%s' (Spec §7.8.2)\n",
				    set[s].vendor_ext.ve_general_flags, path);
				vendor_flags_bad = true;
			} else if (set[s].type == EXFAT_ENTRY_VENDOR_ALLOC) {
				uint8_t vf =
				    set[s].vendor_alloc.va_general_flags;

				if ((vf & ~0x03) != 0 ||
				    (vf & EXFAT_FLAG_ALLOC_POSSIBLE) == 0) {
					pwarn("Invalid flags (0x%02x) in "
					    "Vendor Allocation entry in '%s' "
					    "(Spec §7.9.2)\n", vf, path);
					vendor_flags_bad = true;
				}
			}
		}
	}

	/*
	 * Phase 2: Interactive repair of File Name general flags and
	 * SetChecksum recalculation.
	 */
	if (!*bad_secondary && name_flags_bad) {
		if (ask(1, "Fix file name flags")) {
			for (s = 2; s <= 1 + num_name_entries; s++)
				set[s].name.ne_general_flags = 0;
			exfat_dentry_set_checksum(set, 1 + sec_count);
			if (update_dentry_set(chk, curr_cn, dent, i,
			    sec_count, set, cbuf, entries_per_cluster,
			    no_fat_chain, dir_size, clusters_checked) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	/*
	 * Phase 3: Interactive repair of Vendor secondary general flags and
	 * SetChecksum recalculation.
	 */
	if (!*bad_secondary && vendor_flags_bad) {
		if (ask(1, "Fix vendor secondary flags")) {
			for (s = 2 + num_name_entries; s <= sec_count; s++) {
				if (set[s].type == EXFAT_ENTRY_VENDOR_EXT)
					set[s].vendor_ext.ve_general_flags = 0;
				else if (set[s].type ==
				    EXFAT_ENTRY_VENDOR_ALLOC) {
					uint8_t vf = set[s].vendor_alloc.
					    va_general_flags;

					set[s].vendor_alloc.va_general_flags =
					    (vf & EXFAT_FLAG_NO_FAT_CHAIN) |
					    EXFAT_FLAG_ALLOC_POSSIBLE;
				}
			}
			exfat_dentry_set_checksum(set, 1 + sec_count);
			if (update_dentry_set(chk, curr_cn, dent, i,
			    sec_count, set, cbuf, entries_per_cluster,
			    no_fat_chain, dir_size, clusters_checked) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	return (mod);
}

/*
 * Validate and repair primary File entry reserved fields, timestamps, 10ms
 * increments, and UTC offsets (Spec §7.4.4, §7.4.8-§7.4.10, Table 27).
 *
 * Verifies Reserved1 and attribute flags (Spec §7.4.4), validates create,
 * last modified, and last access timestamps (Spec §7.4.8), 10ms increment
 * values (0-199, Spec §7.4.9), UTC timezone offsets (Spec §7.4.10), and
 * Reserved2 (Spec §7.4, Table 27).  Prompts user to repair corrupted values
 * and updates SetChecksum.
 *
 * Returns FSOK, FSDIRMOD on repair, FSERROR on uncorrected error, or FSFATAL.
 */
static int
check_file_entry_timestamps(struct exfat_chk *chk, uint32_t curr_cn,
    union exfat_dentry *dent, size_t i, size_t sec_count,
    union exfat_dentry *set, uint8_t *cbuf, size_t entries_per_cluster,
    bool no_fat_chain, uint64_t dir_size, uint32_t clusters_checked,
    const char *full_path)
{
	static const uint8_t zero_res2[7] = { 0 };
	uint16_t file_attrs;
	int mod = FSOK;
	bool inc_bad, res2_bad, ts_bad, tz_bad;

	file_attrs = le16toh(set[0].file.fe_file_attributes);

	/*
	 * Phase 1: Validate file entry reserved fields per Spec §7.4 and
	 * attribute flags per Spec §7.4.4.
	 */
	if (set[0].file.fe_reserved1 != 0 || (file_attrs & ~0x0037) != 0) {
		if (set[0].file.fe_reserved1 != 0)
			pwarn("Invalid Reserved1 (0x%04x) in file entry '%s' "
			    "(Spec §7.4)\n",
			    le16toh(set[0].file.fe_reserved1), full_path);
		if ((file_attrs & ~0x0037) != 0)
			pwarn("Invalid reserved attributes (0x%04x) in "
			    "file entry '%s' (Spec §7.4.4)\n",
			    file_attrs & ~0x0037, full_path);
		if (ask(1, "Fix file entry reserved fields")) {
			set[0].file.fe_reserved1 = 0;
			file_attrs &= 0x0037;
			set[0].file.fe_file_attributes = htole16(file_attrs);
			exfat_dentry_set_checksum(set, 1 + sec_count);
			if (update_dentry_set(chk, curr_cn, dent, i,
			    sec_count, set, cbuf, entries_per_cluster,
			    no_fat_chain, dir_size, clusters_checked) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	/*
	 * Phase 2: Validate timestamp, increment, and reserved fields per
	 * Spec §7.4.8-§7.4.10 and Table 27.
	 */
	inc_bad = set[0].file.fe_create_10ms_increment > 199 ||
	    set[0].file.fe_last_modified_10ms_increment > 199;
	tz_bad = !exfat_is_valid_utc_offset(
	    set[0].file.fe_create_tz_offset) ||
	    !exfat_is_valid_utc_offset(
	    set[0].file.fe_last_modified_tz_offset) ||
	    !exfat_is_valid_utc_offset(
	    set[0].file.fe_last_access_tz_offset);
	ts_bad = !exfat_is_valid_timestamp(
	    le32toh(set[0].file.fe_create_timestamp)) ||
	    !exfat_is_valid_timestamp(
	    le32toh(set[0].file.fe_last_modified_timestamp)) ||
	    !exfat_is_valid_timestamp(
	    le32toh(set[0].file.fe_last_access_timestamp));
	res2_bad = memcmp(set[0].file.fe_reserved2, zero_res2,
	    sizeof(zero_res2)) != 0;

	/*
	 * Phase 3: Interactive repair of invalid timestamps, increments,
	 * UTC offsets, and Reserved2 bytes.
	 */
	if (inc_bad || tz_bad || ts_bad || res2_bad) {
		if (inc_bad)
			pwarn("Invalid 10ms increment in file entry '%s' "
			    "(Spec §7.4.9)\n", full_path);
		if (tz_bad)
			pwarn("Invalid UTC offset in file entry '%s' "
			    "(Spec §7.4.10)\n", full_path);
		if (ts_bad)
			pwarn("Invalid timestamp in file entry '%s' "
			    "(Spec §7.4.8)\n", full_path);
		if (res2_bad)
			pwarn("Invalid Reserved2 in file entry '%s' "
			    "(Spec §7.4)\n", full_path);
		if (ask(1, "Fix file timestamp and reserved fields")) {
			if (set[0].file.fe_create_10ms_increment > 199)
				set[0].file.fe_create_10ms_increment = 0;
			if (set[0].file.fe_last_modified_10ms_increment > 199)
				set[0].file.fe_last_modified_10ms_increment = 0;
			if (!exfat_is_valid_utc_offset(
			    set[0].file.fe_create_tz_offset))
				set[0].file.fe_create_tz_offset = 0;
			if (!exfat_is_valid_utc_offset(
			    set[0].file.fe_last_modified_tz_offset))
				set[0].file.fe_last_modified_tz_offset = 0;
			if (!exfat_is_valid_utc_offset(
			    set[0].file.fe_last_access_tz_offset))
				set[0].file.fe_last_access_tz_offset = 0;
			if (!exfat_is_valid_timestamp(
			    le32toh(set[0].file.fe_create_timestamp)))
				set[0].file.fe_create_timestamp = 0;
			if (!exfat_is_valid_timestamp(
			    le32toh(set[0].file.fe_last_modified_timestamp)))
				set[0].file.fe_last_modified_timestamp = 0;
			if (!exfat_is_valid_timestamp(
			    le32toh(set[0].file.fe_last_access_timestamp)))
				set[0].file.fe_last_access_timestamp = 0;
			if (res2_bad)
				memset(set[0].file.fe_reserved2, 0,
				    sizeof(set[0].file.fe_reserved2));
			exfat_dentry_set_checksum(set, 1 + sec_count);
			if (update_dentry_set(chk, curr_cn, dent, i,
			    sec_count, set, cbuf, entries_per_cluster,
			    no_fat_chain, dir_size, clusters_checked) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	return (mod);
}

/*
 * Validate and track clusters allocated to Vendor Allocation secondary
 * directory entries in a file directory set (Spec §7.9).
 *
 * Scans for Vendor Allocation entries (0xE1), checks cluster heap bounds,
 * validates NoFatChain vs FAT-chained allocations, detects truncated FAT
 * chains, and records allocated clusters in chk->used_bitmap.
 *
 * Returns FSOK, or FSERROR if any allocation is corrupted.
 */
static int
check_vendor_allocations(struct exfat_chk *chk, const union exfat_dentry *set,
    size_t sec_count, size_t num_name_entries, const char *full_path)
{
	size_t s;
	int mod = FSOK;

	/*
	 * Phase 1: Locate Vendor Allocation secondary entries (Spec §7.9).
	 */
	for (s = 2 + num_name_entries; s <= sec_count; s++) {
		const struct exfat_dentry_vendor_alloc *va;
		uint64_t c_idx, va_len, va_need;
		uint32_t scn, va_cn;
		bool va_no_fat;

		if (set[s].type != EXFAT_ENTRY_VENDOR_ALLOC)
			continue;

		va = &set[s].vendor_alloc;
		va_cn = le32toh(va->va_first_cluster);
		va_len = le64toh(va->va_data_length);
		va_no_fat = (va->va_general_flags &
		    EXFAT_FLAG_NO_FAT_CHAIN) != 0;

		if (va_len == 0)
			continue;

		/*
		 * Phase 2: Allocation boundary and cluster heap validation.
		 */
		if (!EXFAT_CLUSTER_VALID(chk, va_cn)) {
			pwarn("Vendor Allocation in '%s' has invalid first "
			    "cluster %u (Spec §7.9)\n", full_path, va_cn);
			mod |= FSERROR;
			continue;
		}
		if (va_len > UINT64_MAX - (chk->boot.cluster_size - 1)) {
			pwarn("Vendor Allocation in '%s' has invalid length "
			    "%ju (Spec §7.9)\n", full_path, (uintmax_t)va_len);
			mod |= FSERROR;
			continue;
		}
		va_need = howmany(va_len, chk->boot.cluster_size);
		if (va_need > chk->boot.cluster_count ||
		    (va_no_fat && (uint64_t)EXFAT_CNTOI(va_cn) + va_need >
		    chk->boot.cluster_count)) {
			pwarn("Vendor Allocation in '%s' extends beyond "
			    "cluster heap (clusters: %ju, heap: %u) "
			    "(Spec §7.9)\n", full_path, (uintmax_t)va_need,
			    chk->boot.cluster_count);
			mod |= FSERROR;
			continue;
		}

		/*
		 * Phase 3: Cluster traversal and allocation tracking in
		 * used bitmap.
		 */
		scn = va_cn;
		c_idx = 0;
		while (c_idx < va_need && EXFAT_CLUSTER_VALID(chk, scn)) {
			mod |= mark_cluster_used(chk, scn, full_path);
			c_idx++;
			if (va_no_fat)
				scn++;
			else if (fat_get(chk, scn, &scn) != 0)
				break;
		}
		if (!va_no_fat && c_idx < va_need) {
			pwarn("Vendor Allocation in '%s' has truncated FAT "
			    "chain (clusters: %ju, expected: %ju) "
			    "(Spec §7.9)\n", full_path, (uintmax_t)c_idx,
			    (uintmax_t)va_need);
			mod |= FSERROR;
		}
	}

	return (mod);
}

/*
 * Reconstruct filename from File Name entries, validate name characters,
 * and verify/repair NameHash (Spec §7.7 and §7.6.4).
 */
static int
check_file_name_and_hash(struct exfat_chk *chk, uint32_t curr_cn,
    union exfat_dentry *dent, size_t d_idx, uint8_t sec_count,
    union exfat_dentry *set, void *cbuf, size_t entries_per_cluster,
    bool no_fat_chain, uint64_t dir_size, size_t clusters_checked,
    size_t num_name_entries, const char *path, char *full_path,
    size_t full_path_size, char *name_utf8, size_t name_utf8_size)
{
	uint16_t utf16_name[EXFAT_MAX_NAME_CHARS + 1];
	uint16_t calc_hash = 0, exp_hash;
	size_t name_chars = 0;
	uint8_t name_len;
	int mod = FSOK;

	name_len = set[1].stream.se_name_length;
	exp_hash = le16toh(set[1].stream.se_name_hash);

	for (size_t s = 2; s <= 1 + num_name_entries; s++) {
		const struct exfat_dentry_name *ne = &set[s].name;

		for (size_t c_idx = 0;
		    c_idx < EXFAT_CHARS_PER_NAME_ENTRY &&
		    name_chars < name_len; c_idx++) {
			uint16_t ch = le16toh(ne->ne_file_name[c_idx]);
			uint16_t up_ch;

			utf16_name[name_chars++] = ch;
			up_ch = chk->upcase_table[ch];
			calc_hash = exfat_calc_name_hash(up_ch, calc_hash);
		}
	}
	utf16_name[name_chars] = 0;

	exfat_utf16_to_utf8(utf16_name, name_chars, name_utf8, name_utf8_size);
	if (path[0] == '\0')
		snprintf(full_path, full_path_size, "%s", name_utf8);
	else
		snprintf(full_path, full_path_size, "%s/%s", path, name_utf8);

	if (name_chars != name_len) {
		pwarn("Name length mismatch for '%s': found %zu chars, "
		    "expected %u\n", full_path, name_chars, name_len);
		mod |= FSERROR;
	} else if (!exfat_is_valid_name(utf16_name, name_chars)) {
		bool all_spaces = true;

		for (size_t k = 0; k < name_chars; k++) {
			if (utf16_name[k] != 0x0020) {
				all_spaces = false;
				break;
			}
		}
		if (all_spaces)
			pwarn("File name consists entirely of spaces: '%s'\n",
			    full_path);
		else
			pwarn("Invalid character in file name '%s'\n",
			    full_path);
		mod |= FSERROR;
	} else if (calc_hash != exp_hash) {
		pwarn("Name hash mismatch for '%s': 0x%04x != 0x%04x\n",
		    full_path, calc_hash, exp_hash);
		if (ask(1, "Fix file name hash")) {
			set[1].stream.se_name_hash = htole16(calc_hash);
			exfat_dentry_set_checksum(set, 1 + sec_count);
			if (update_dentry_set(chk, curr_cn, dent, d_idx,
			    sec_count, set, cbuf, entries_per_cluster,
			    no_fat_chain, dir_size, clusters_checked) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	return (mod);
}

/*
 * Validate and repair Stream Extension flags (Spec §7.6.2) and reserved fields
 * (Spec §7.6 Table 33).
 */
static int
check_stream_flags_and_reserved(struct exfat_chk *chk, uint32_t curr_cn,
    union exfat_dentry *dent, size_t d_idx, uint8_t sec_count,
    union exfat_dentry *set, void *cbuf, size_t entries_per_cluster,
    bool no_fat_chain, uint64_t dir_size, size_t clusters_checked,
    uint32_t first_cn, uint64_t data_len, const char *full_path,
    bool *file_no_fat_chain)
{
	struct exfat_dentry_stream *se = &set[1].stream;
	uint8_t exp_flags, flags;
	int mod = FSOK;

	flags = se->se_general_flags;
	exp_flags = flags | EXFAT_FLAG_ALLOC_POSSIBLE;
	if (first_cn == 0 || data_len == 0)
		exp_flags &= ~EXFAT_FLAG_NO_FAT_CHAIN;
	exp_flags &= (EXFAT_FLAG_ALLOC_POSSIBLE | EXFAT_FLAG_NO_FAT_CHAIN);

	if (flags != exp_flags) {
		pwarn("Stream flags mismatch for '%s': 0x%02x != 0x%02x "
		    "(Spec §7.6.2)\n", full_path, flags, exp_flags);
		if (ask(1, "Fix stream flags")) {
			se->se_general_flags = exp_flags;
			*file_no_fat_chain = (exp_flags &
			    EXFAT_FLAG_NO_FAT_CHAIN) != 0;
			exfat_dentry_set_checksum(set, 1 + sec_count);
			if (update_dentry_set(chk, curr_cn, dent, d_idx,
			    sec_count, set, cbuf, entries_per_cluster,
			    no_fat_chain, dir_size, clusters_checked) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	/*
	 * Validate Stream Extension reserved fields per Spec §7.6 (Table 33).
	 */
	if (se->se_reserved1 != 0 || se->se_reserved2 != 0 ||
	    se->se_reserved3 != 0) {
		pwarn("Non-zero reserved fields in Stream Extension entry '%s' "
		    "(Spec §7.6)\n", full_path);
		if (ask(1, "Fix stream extension reserved fields")) {
			se->se_reserved1 = 0;
			se->se_reserved2 = 0;
			se->se_reserved3 = 0;
			exfat_dentry_set_checksum(set, 1 + sec_count);
			if (update_dentry_set(chk, curr_cn, dent, d_idx,
			    sec_count, set, cbuf, entries_per_cluster,
			    no_fat_chain, dir_size, clusters_checked) == 0)
				mod |= FSDIRMOD;
			else
				mod |= FSFATAL;
		} else
			mod |= FSERROR;
	}

	return (mod);
}

/*
 * Inspect and repair directory entries in a directory cluster chain
 * recursively.
 *
 * Traverses directory clusters, validates primary File Directory Entries
 * (Spec §7.4), Stream Extension entries (Spec §7.6), File Name entries (Spec
 * §7.7), and secondary entries.  Verifies entry set checksums (Spec §7.4.3),
 * NameHash values (Spec §7.6.4), Unicode file names, timestamps
 * (Spec §7.4.8), stream allocation flags (Spec §7.6.2 / §6.4.2), and cluster
 * chains.  Recurses into child directory hierarchies down to MAX_DIR_DEPTH.
 *
 * Returns FSOK, FSDIRMOD, FSFATMOD, FSERROR, or FSFATAL.
 */
static int
check_dir_cluster(struct exfat_chk *chk, uint32_t dir_cluster,
    const char *path, int depth, uint64_t dir_size, bool no_fat_chain)
{
	uint8_t *cbuf;
	uint32_t curr_cn, prev_cn = 0;
	int mod = FSOK;
	size_t entries_per_cluster;
	uint32_t loop_count = 0;
	uint64_t clusters_checked = 0, needed_clusters;
	size_t skip, skip_entries = 0;
	bool eod_seen = false;

	if (depth > MAX_DIR_DEPTH) {
		pwarn(
		    "Maximum directory nesting depth exceeded at '%s'\n",
		    path);
		return (FSERROR);
	}

	if (!EXFAT_CLUSTER_VALID(chk, dir_cluster)) {
		pwarn("Directory '%s' starts with invalid cluster %u\n",
		    path, dir_cluster);
		return (FSERROR);
	}

	cbuf = malloc(chk->boot.cluster_size);
	if (cbuf == NULL) {
		perr("Out of memory allocating cluster buffer");
		return (FSFATAL);
	}

	entries_per_cluster = chk->boot.cluster_size /
	    sizeof(union exfat_dentry);
	curr_cn = dir_cluster;

	/*
	 * Phase 1: Directory cluster chain traversal and cycle protection.
	 *
	 * Traverse the directory's cluster chain, marking visited clusters in
	 * the used bitmap and guarding against cycles or cross-links.
	 */
	while (EXFAT_CLUSTER_VALID(chk, curr_cn)) {
		union exfat_dentry *dent;
		size_t i;

		if (++loop_count > chk->boot.cluster_count) {
			pwarn("Cycle loop detected in directory cluster chain "
			    "at '%s'\n", path);
			free(cbuf);
			return (mod | FSERROR);
		}

		if (is_cluster_used(chk, curr_cn)) {
			pwarn("Cycle loop detected in directory cluster chain "
			    "at '%s'\n", path);
			if (!no_fat_chain && prev_cn != 0 &&
			    ask(1, "Break directory cluster loop")) {
				fat_set(chk, prev_cn, EXFAT_FAT_EOF);
				mod |= FSFATMOD;
			} else
				mod |= mark_cluster_used(chk, curr_cn, path);
			break;
		}

		/* Mark cluster used by directory */
		mod |= mark_cluster_used(chk, curr_cn, path);

		if (!eod_seen) {
			if (read_cluster(chk, curr_cn, cbuf) != 0) {
				free(cbuf);
				return (mod | FSERROR);
			}

			dent = (union exfat_dentry *)cbuf;
			skip = skip_entries < entries_per_cluster ?
			    skip_entries : entries_per_cluster;
			skip_entries -= skip;
		} else {
			dent = NULL;
			skip = entries_per_cluster;
		}

		/*
		 * Phase 2: Individual entry screening.
		 *
		 * Scan entries for EOD termination, remove orphaned secondary
		 * entries, reject root-only metadata entries in subdirectories,
		 * and purge unrecognized critical directory entries.
		 */
		for (i = skip; i < entries_per_cluster; i++) {
			uint8_t type = dent[i].type;

			if (type == EXFAT_ENTRY_EOD) {
				eod_seen = true;
				break;
			}
			if ((type & EXFAT_ENTRY_TYPE_IN_USE) == 0)
				continue;

			if ((type & EXFAT_ENTRY_TYPE_SECONDARY) != 0) {
				pwarn("Orphaned secondary directory entry "
				    "(0x%02x) in '%s'\n", type, path);
				if (ask(1, "Remove orphaned entry")) {
					dent[i].type &=
					    ~EXFAT_ENTRY_TYPE_IN_USE;
					if (write_cluster(chk, curr_cn,
					    cbuf) == 0)
						mod |= FSDIRMOD;
					else
						mod |= FSFATAL;
				} else
					mod |= FSERROR;
				continue;
			}

			if (depth > 0 &&
			    (type == EXFAT_ENTRY_BITMAP ||
			    type == EXFAT_ENTRY_UPCASE ||
			    type == EXFAT_ENTRY_VOLUME_LABEL ||
			    type == EXFAT_ENTRY_VOLUME_GUID)) {
				pwarn("Root-only directory entry (0x%02x) "
				    "found in subdirectory '%s'\n", type, path);
				if (ask(1, "Remove invalid entry")) {
					dent[i].type &=
					    ~EXFAT_ENTRY_TYPE_IN_USE;
					if (write_cluster(chk, curr_cn,
					    cbuf) == 0)
						mod |= FSDIRMOD;
					else
						mod |= FSFATAL;
				} else
					mod |= FSERROR;
				continue;
			}

			if ((type & EXFAT_ENTRY_TYPE_BENIGN) == 0 &&
			    type != EXFAT_ENTRY_FILE &&
			    type != EXFAT_ENTRY_BITMAP &&
			    type != EXFAT_ENTRY_UPCASE &&
			    type != EXFAT_ENTRY_VOLUME_LABEL) {
				pwarn("Unrecognized critical directory entry "
				    "(0x%02x) in '%s'\n", type, path);
				if (ask(1, "Remove unrecognized entry")) {
					dent[i].type &=
					    ~EXFAT_ENTRY_TYPE_IN_USE;
					if (write_cluster(chk, curr_cn,
					    cbuf) == 0)
						mod |= FSDIRMOD;
					else
						mod |= FSFATAL;
				} else
					mod |= FSERROR;
				continue;
			}

			if (type == EXFAT_ENTRY_TEXFAT_PADDING) {
				mod |= check_texfat_padding_entry(chk, &dent[i],
				    curr_cn, cbuf, path);
				continue;
			}

			if (type == EXFAT_ENTRY_FILE) {
				struct exfat_dentry_file *fe = &dent[i].file;
				struct exfat_dentry_stream *se;
				union exfat_dentry set[MAX_ENTRY_SET];
				char name_utf8[EXFAT_MAX_NAME_CHARS * 4 + 1];
				char full_path[PATH_MAX];
				uint8_t sec_count = fe->fe_secondary_count;
				uint16_t exp_csum, calc_csum;
				uint16_t file_attrs =
				    le16toh(fe->fe_file_attributes);
				uint64_t data_len, valid_len;
				uint32_t first_cn;
				uint8_t name_len, num_name_entries;
				size_t s;
				bool is_dir =
				    (file_attrs & EXFAT_ATTR_DIRECTORY) != 0;
				bool bad_secondary, file_no_fat_chain;

				if (sec_count < EXFAT_MIN_SECONDARY_COUNT) {
					pwarn("Invalid secondary count %u for "
					    "file entry in '%s'\n", sec_count,
					    path);
					if (ask(0, "Remove corrupted entry")) {
						dent[i].type &=
						    ~EXFAT_ENTRY_TYPE_IN_USE;
						if (write_cluster(chk, curr_cn,
						    cbuf) == 0)
							mod |= FSDIRMOD;
						else
							mod |= FSFATAL;
					} else
						mod |= FSERROR;
					continue;
				}

				/*
				 * Phase 3: Directory entry set assembly.
				 *
				 * Collect the primary File Directory Entry
				 * and secondary entries (handling entries
				 * straddling cluster boundaries).
				 */
				set[0] = dent[i];
				if (i + 1 + sec_count <= entries_per_cluster)
					for (s = 1; s <= sec_count; s++)
						set[s] = dent[i + s];
				else {
					/* Entry set straddles boundary */
					size_t cur_avail =
					    entries_per_cluster - i - 1;
					uint32_t next_cn;

					for (s = 1; s <= cur_avail; s++)
						set[s] = dent[i + s];

					if (no_fat_chain) {
						if (dir_size > 0 &&
						    (clusters_checked + 1) *
						    chk->boot.cluster_size >=
						    dir_size)
							next_cn = EXFAT_FAT_EOF;
						else
							next_cn = curr_cn + 1;
					} else if (fat_get(chk, curr_cn,
					    &next_cn) != 0)
						next_cn = EXFAT_FAT_EOF;

					read_straddled_entries(chk, next_cn,
					    set, cur_avail, sec_count,
					    no_fat_chain, dir_size,
					    clusters_checked);
					if (EXFAT_CLUSTER_VALID(chk, next_cn))
						skip_entries = sec_count -
						    cur_avail;
				}

				/*
				 * Phase 4: Stream extension and filename
				 * validation.
				 *
				 * Validate Stream Extension Entry (Spec
				 * Section 7.6) and File Name Entries (Spec
				 * Section 7.7), verify NameHash, ensure
				 * ValidDataLength <= DataLength, check
				 * stream flags (Spec Section 7.6.2 / 6.4.2),
				 * and recurse into child directories or
				 * invoke check_file_clusters().
				 */
				if (set[1].type != EXFAT_ENTRY_STREAM) {
					uint8_t actual_sec =
					    count_secondary_entries(set,
					    sec_count);

					pwarn("Expected Stream Extension entry "
					    "(0xC0) in '%s', found 0x%02x\n",
					    path, set[1].type);
					if (ask(0,
					    "Remove corrupted entry set")) {
						if (delete_dentry_set(chk,
						    curr_cn, dent, i,
						    actual_sec, cbuf,
						    entries_per_cluster,
						    no_fat_chain, dir_size,
						    clusters_checked) == 0)
							mod |= FSDIRMOD;
						else
							mod |= FSFATAL;
					} else
						mod |= FSERROR;
					if (skip_entries > 0) {
						size_t cur_avail =
						    entries_per_cluster - i - 1;

						skip_entries = actual_sec >
						    cur_avail ? actual_sec -
						    cur_avail : 0;
					}
					i += actual_sec;
					continue;
				}

				se = &set[1].stream;
				name_len = se->se_name_length;
				data_len = le64toh(se->se_data_length);
				valid_len = le64toh(se->se_valid_data_length);
				first_cn = le32toh(se->se_first_cluster);
				file_no_fat_chain = (se->se_general_flags &
				    EXFAT_FLAG_NO_FAT_CHAIN) != 0;

				num_name_entries = howmany(name_len,
				    EXFAT_CHARS_PER_NAME_ENTRY);
				bad_secondary = false;

				if (name_len == 0 ||
				    sec_count < 1 + num_name_entries) {
					pwarn("Invalid name length %u or "
					    "secondary count %u for file "
					    "entry in '%s'\n", name_len,
					    sec_count, path);
					bad_secondary = true;
				} else
					mod |= check_file_secondary_flags(chk,
					    curr_cn, dent, i, sec_count,
					    num_name_entries, set, cbuf,
					    entries_per_cluster, no_fat_chain,
					    dir_size, clusters_checked,
					    path, &bad_secondary);

				if (bad_secondary) {
					uint8_t actual_sec =
					    count_secondary_entries(set,
					    sec_count);

					if (ask(0,
					    "Remove corrupted entry set")) {
						if (delete_dentry_set(chk,
						    curr_cn, dent, i,
						    actual_sec, cbuf,
						    entries_per_cluster,
						    no_fat_chain, dir_size,
						    clusters_checked) == 0)
							mod |= FSDIRMOD;
						else
							mod |= FSFATAL;
					} else
						mod |= FSERROR;
					if (skip_entries > 0) {
						size_t cur_avail =
						    entries_per_cluster - i - 1;

						skip_entries = actual_sec >
						    cur_avail ? actual_sec -
						    cur_avail : 0;
					}
					i += actual_sec;
					continue;
				}

				/*
				 * Verify directory entry set checksum per
				 * Spec Section 7.4.3.
				 */
				calc_csum = exfat_dentry_calc_checksum(set,
				    1 + sec_count);
				exp_csum =
				    le16toh(set[0].file.fe_set_checksum);

				if (calc_csum != exp_csum) {
					pwarn(
					    "Directory entry set checksum "
					    "mismatch in '%s': 0x%04x != "
					    "0x%04x\n",
					    path, calc_csum, exp_csum);
					if (ask(1, "Fix entry set checksum")) {
						exfat_dentry_set_checksum(set,
						    1 + sec_count);
						if (update_dentry_set(chk,
						    curr_cn, dent, i,
						    sec_count, set, cbuf,
						    entries_per_cluster,
						    no_fat_chain, dir_size,
						    clusters_checked) == 0)
							mod |= FSDIRMOD;
						else
							mod |= FSFATAL;
					} else
						mod |= FSERROR;
				}

				if (valid_len > data_len) {
					pwarn("Valid data length (%ju) exceeds "
					    "data length (%ju) in '%s'\n",
					    valid_len, data_len, path);
					if (ask(1, "Fix valid data length")) {
						valid_len = data_len;
						se->se_valid_data_length =
						    htole64(valid_len);
						exfat_dentry_set_checksum(set,
						    1 + sec_count);
						if (update_dentry_set(chk,
						    curr_cn, dent, i,
						    sec_count, set, cbuf,
						    entries_per_cluster,
						    no_fat_chain, dir_size,
						    clusters_checked) == 0)
							mod |= FSDIRMOD;
						else
							mod |= FSFATAL;
					} else
						mod |= FSERROR;
				} else if (is_dir && valid_len != data_len) {
					pwarn("Directory '%s' valid length "
					    "(%ju) != data length (%ju)\n",
					    path, valid_len, data_len);
					if (ask(1,
					    "Fix directory valid length")) {
						valid_len = data_len;
						se->se_valid_data_length =
						    htole64(valid_len);
						exfat_dentry_set_checksum(set,
						    1 + sec_count);
						if (update_dentry_set(chk,
						    curr_cn, dent, i,
						    sec_count, set, cbuf,
						    entries_per_cluster,
						    no_fat_chain, dir_size,
						    clusters_checked) == 0)
							mod |= FSDIRMOD;
						else
							mod |= FSFATAL;
					} else
						mod |= FSERROR;
				}

				if (is_dir) {
					if (data_len > EXFAT_MAX_DIR_SIZE) {
						pwarn("Directory '%s' size "
						    "exceeds 256MB (%ju)\n",
						    path, data_len);
						mod |= FSERROR;
					}
					if (data_len > 0 &&
					    (data_len %
					    chk->boot.cluster_size) != 0) {
						pwarn("Directory '%s' size is "
						    "not a cluster multiple\n",
						    path);
						mod |= FSERROR;
					}
				}

				/* Reconstruct filename and verify hash */
				mod |= check_file_name_and_hash(chk, curr_cn,
				    dent, i, sec_count, set, cbuf,
				    entries_per_cluster, no_fat_chain,
				    dir_size, clusters_checked,
				    num_name_entries, path, full_path,
				    sizeof(full_path), name_utf8,
				    sizeof(name_utf8));

				mod |= check_file_entry_timestamps(chk, curr_cn,
				    dent, i, sec_count, set, cbuf,
				    entries_per_cluster, no_fat_chain,
				    dir_size, clusters_checked, full_path);

				/*
				 * Phase 5: Stream flags, reserved fields, and
				 * cluster allocation checks (Spec §7.6.2,
				 * §7.6).
				 *
				 * Validate and repair stream general flags
				 * (AllocPossible, NoFatChain), zero reserved
				 * fields, verify file data cluster allocations
				 * via check_file_clusters(), and track vendor
				 * allocations.
				 */
				mod |= check_stream_flags_and_reserved(chk,
				    curr_cn, dent, i, sec_count, set, cbuf,
				    entries_per_cluster, no_fat_chain,
				    dir_size, clusters_checked, first_cn,
				    data_len, full_path, &file_no_fat_chain);

				/* Verify cluster allocation for data stream */
				if (!is_dir)
					mod |= check_file_clusters(chk,
					    full_path, se, dent, set, i,
					    sec_count, cbuf,
					    entries_per_cluster, no_fat_chain,
					    dir_size, clusters_checked,
					    curr_cn);

				/* Track vendor allocation secondary entries */
				if (!bad_secondary)
					mod |= check_vendor_allocations(chk,
					    set, sec_count, num_name_entries,
					    full_path);

				/*
				 * Phase 6: Subdirectory recursion and child
				 * traversal.
				 *
				 * Validate directory starting cluster and size
				 * bounds, track LOST.DIR runtime state, and
				 * recurse into child directories down to
				 * MAX_DIR_DEPTH.
				 */
				if (is_dir) {
					chk->num_dirs++;
					if (first_cn == 0) {
						pwarn("Directory '%s' starts "
						    "with invalid cluster 0\n",
						    full_path);
						mod |= FSERROR;
					} else if (data_len == 0 &&
					    file_no_fat_chain) {
						pwarn("Contiguous directory "
						    "'%s' has zero size "
						    "(Spec §6.4.2)\n",
						    full_path);
						mod |= FSERROR;
					} else if (!EXFAT_CLUSTER_VALID(chk,
					    first_cn)) {
						pwarn("Directory '%s' starts "
						    "with invalid cluster %u\n",
						    full_path, first_cn);
						mod |= FSERROR;
					} else {
						if (depth == 0 &&
						    strcasecmp(name_utf8,
						    "LOST.DIR") == 0) {
							chk->lostdir_found =
							    true;
							chk->lostdir_cluster =
							    first_cn;
							chk->lostdir_dentry_cn =
							    curr_cn;
							chk->
							    lostdir_dentry_idx =
							    i;
							chk->lostdir_size =
							    data_len;
							chk->
							    lostdir_no_fat_chain
							    = file_no_fat_chain;
						}
						mod |= check_dir_cluster(chk,
						    first_cn, full_path,
						    depth + 1, data_len,
						    file_no_fat_chain);
					}
				} else
					chk->num_files++;

				i += sec_count;
			}
		}

		/*
		 * Phase 7: Cluster chain stepping and reconciliation.
		 *
		 * Advance to next cluster in directory chain (supporting both
		 * NoFatChain contiguous allocations and FAT-chained stepping),
		 * validate FAT terminators, and reconcile total clusters
		 * against expected directory size.
		 */
		clusters_checked++;
		prev_cn = curr_cn;

		if (no_fat_chain) {
			needed_clusters = (dir_size / chk->boot.cluster_size) +
			    ((dir_size % chk->boot.cluster_size) != 0);
			if (dir_size > 0 &&
			    clusters_checked < needed_clusters) {
				if (EXFAT_CNTOI(curr_cn) + 1 >=
				    chk->boot.cluster_count) {
					pwarn("Directory '%s' cluster range "
					    "exceeds cluster heap\n", path);
					mod |= FSERROR;
					break;
				}
				curr_cn++;
			} else
				break;
		} else {
			if (fat_get(chk, curr_cn, &curr_cn) != 0) {
				free(cbuf);
				return (mod | FSERROR);
			}
			if (!EXFAT_CLUSTER_VALID(chk, curr_cn) &&
			    !EXFAT_FAT_IS_EOF(curr_cn)) {
				pwarn("Invalid FAT entry 0x%08x in directory "
				    "'%s' at cluster %u\n", curr_cn, path,
				    prev_cn);
				if (ask(1, "Terminate directory FAT chain "
				    "with EOF")) {
					fat_set(chk, prev_cn, EXFAT_FAT_EOF);
					mod |= FSFATMOD;
				} else
					mod |= FSERROR;
				break;
			}
		}
	}

	if (depth > 0 && !no_fat_chain && dir_size > 0) {
		needed_clusters = (dir_size / chk->boot.cluster_size) +
		    ((dir_size % chk->boot.cluster_size) != 0);
		if (clusters_checked < needed_clusters) {
			pwarn("Directory '%s' FAT chain has %ju clusters, "
			    "expected %ju\n", path,
			    (uintmax_t)clusters_checked,
			    (uintmax_t)needed_clusters);
			mod |= FSERROR;
		} else if (clusters_checked > needed_clusters) {
			pwarn("Directory '%s' has %ju superfluous clusters "
			    "(%ju > %ju)\n", path,
			    (uintmax_t)(clusters_checked - needed_clusters),
			    (uintmax_t)clusters_checked,
			    (uintmax_t)needed_clusters);
			mod |= FSERROR;
		}
	}

	free(cbuf);
	return (mod);
}

/*
 * Top-level entry point for directory tree verification.
 *
 * Initiates recursive directory tree traversal starting from the root
 * directory cluster (depth 0), checking directory structure, entry sets,
 * and file cluster chains throughout the filesystem.
 *
 * Returns FSOK, FSDIRMOD, FSERROR, or FSFATAL.
 */
int
check_dirtree(struct exfat_chk *chk)
{
	/* Recursively traverse starting from root directory */
	return (check_dir_cluster(chk, chk->boot.root_dir_cluster, "", 0, 0,
	    false));
}

/*
 * Create a LOST.DIR directory in the root directory for recovered files.
 *
 * Searches root directory clusters for three contiguous available entry slots,
 * allocates a free cluster from the cluster heap, formats the File (0x85),
 * Stream Extension (0xC0), and File Name (0xC1) entries, calculates SetChecksum
 * (Spec §7.4.3), writes the directory set into root, and initializes LOST.DIR
 * check state.
 *
 * Returns 0 on success, ENOSPC if no slots or clusters are free, or an I/O
 * error.
 */
static int
create_lost_dir(struct exfat_chk *chk)
{
	union exfat_dentry *dent, set[3];
	const char *ld_name = "LOST.DIR";
	uint8_t *cbuf;
	size_t entries_per_cluster, j, k, slot_idx;
	uint32_t c, eod_cn, free_cn, root_cn, slot_cn, walked;
	uint16_t hash;
	bool slot_found, was_eod;

	cbuf = malloc(chk->boot.cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	root_cn = chk->boot.root_dir_cluster;
	entries_per_cluster = chk->boot.cluster_size /
	    sizeof(union exfat_dentry);
	slot_found = false;
	slot_idx = 0;
	slot_cn = 0;
	eod_cn = 0;
	walked = 0;

	/*
	 * Phase 1: Search root directory for three contiguous available slots.
	 */
	while (EXFAT_CLUSTER_VALID(chk, root_cn)) {
		if (++walked > chk->boot.cluster_count)
			break;
		if (read_cluster(chk, root_cn, cbuf) != 0) {
			free(cbuf);
			return (EIO);
		}
		dent = (union exfat_dentry *)cbuf;
		for (k = 0; k + 3 <= entries_per_cluster; k++) {
			bool empty = true;

			for (j = 0; j < 3; j++) {
				uint8_t t = dent[k + j].type;

				if (t == EXFAT_ENTRY_EOD)
					break;
				if ((t & EXFAT_ENTRY_TYPE_IN_USE) != 0) {
					empty = false;
					break;
				}
			}
			if (empty) {
				slot_found = true;
				slot_idx = k;
				slot_cn = root_cn;
				break;
			}
		}
		if (slot_found)
			break;
		for (k = 0; k < entries_per_cluster; k++) {
			if (dent[k].type == EXFAT_ENTRY_EOD) {
				eod_cn = root_cn;
				break;
			}
		}
		if (fat_get(chk, root_cn, &root_cn) != 0)
			break;
	}

	if (!slot_found) {
		free(cbuf);
		return (ENOSPC);
	}

	/*
	 * Phase 2: Allocate a free cluster from the cluster heap.
	 */
	free_cn = 0;
	for (c = 0; c < chk->boot.cluster_count; c++) {
		uint32_t idx = c / 8;
		uint8_t mask = 1U << (c % 8);
		uint32_t val;

		if (fat_get(chk, EXFAT_ITOCN(c), &val) == 0 &&
		    EXFAT_FAT_IS_BAD(val))
			continue;
		if (!(chk->disk_bitmap[idx] & mask) &&
		    !(chk->used_bitmap[idx] & mask)) {
			free_cn = EXFAT_ITOCN(c);
			break;
		}
	}
	if (free_cn == 0) {
		for (c = 0; c < chk->boot.cluster_count; c++) {
			uint32_t idx = c / 8;
			uint8_t mask = 1U << (c % 8);
			uint32_t val;

			if (fat_get(chk, EXFAT_ITOCN(c), &val) == 0 &&
			    EXFAT_FAT_IS_BAD(val))
				continue;
			if ((chk->disk_bitmap[idx] & mask) &&
			    !(chk->used_bitmap[idx] & mask)) {
				free_cn = EXFAT_ITOCN(c);
				break;
			}
		}
	}
	if (free_cn == 0) {
		free(cbuf);
		return (ENOSPC);
	}

	/*
	 * Phase 3: Format the directory cluster and update allocation
	 * tracking.
	 */
	memset(cbuf, 0, chk->boot.cluster_size);
	if (write_cluster(chk, free_cn, cbuf) != 0) {
		free(cbuf);
		return (EIO);
	}
	fat_set(chk, free_cn, EXFAT_FAT_EOF);
	chk->disk_bitmap[EXFAT_CNTOI(free_cn) / 8] |=
	    1U << (EXFAT_CNTOI(free_cn) % 8);
	chk->used_bitmap[EXFAT_CNTOI(free_cn) / 8] |=
	    1U << (EXFAT_CNTOI(free_cn) % 8);

	/*
	 * Phase 4: Construct the 3-entry directory set and compute SetChecksum
	 * (Spec §7.4.3).
	 */
	memset(set, 0, sizeof(set));
	set[0].type = EXFAT_ENTRY_FILE;
	set[0].file.fe_secondary_count = 2;
	set[0].file.fe_file_attributes = htole16(EXFAT_ATTR_DIRECTORY);

	hash = 0;
	for (j = 0; j < 8; j++) {
		uint16_t up = chk->upcase_table[(unsigned char)ld_name[j]];

		hash = exfat_calc_name_hash(up, hash);
	}

	set[1].type = EXFAT_ENTRY_STREAM;
	set[1].stream.se_general_flags = EXFAT_FLAG_ALLOC_POSSIBLE;
	set[1].stream.se_name_length = 8;
	set[1].stream.se_name_hash = htole16(hash);
	set[1].stream.se_first_cluster = htole32(free_cn);
	set[1].stream.se_data_length = htole64(chk->boot.cluster_size);
	set[1].stream.se_valid_data_length = htole64(chk->boot.cluster_size);

	set[2].type = EXFAT_ENTRY_NAME;
	for (j = 0; j < 8; j++)
		set[2].name.ne_file_name[j] = htole16((uint16_t)ld_name[j]);

	exfat_dentry_set_checksum(set, 3);

	/*
	 * Phase 5: Insert entry set into root directory and preserve EOD
	 * invariants (Spec §6.2.1).
	 */
	if (read_cluster(chk, slot_cn, cbuf) != 0) {
		fat_set(chk, free_cn, EXFAT_FAT_FREE);
		chk->disk_bitmap[EXFAT_CNTOI(free_cn) / 8] &=
		    ~(1U << (EXFAT_CNTOI(free_cn) % 8));
		chk->used_bitmap[EXFAT_CNTOI(free_cn) / 8] &=
		    ~(1U << (EXFAT_CNTOI(free_cn) % 8));
		free(cbuf);
		return (EIO);
	}
	dent = (union exfat_dentry *)cbuf;
	was_eod = (dent[slot_idx].type == EXFAT_ENTRY_EOD ||
	    dent[slot_idx + 1].type == EXFAT_ENTRY_EOD ||
	    dent[slot_idx + 2].type == EXFAT_ENTRY_EOD);
	memcpy(&dent[slot_idx], set, sizeof(set));
	/*
	 * If an EOD (0x00) marker was overwritten, terminate the directory
	 * by placing a new EXFAT_ENTRY_EOD immediately after the set
	 * (slot_idx + 3). Per exFAT Spec §6.2.1, a single EOD marker stops
	 * directory traversal, rendering all subsequent slots in the cluster
	 * unallocated without needing to zero them.
	 */
	if (was_eod && slot_idx + 3 < entries_per_cluster)
		dent[slot_idx + 3].type = EXFAT_ENTRY_EOD;

	if (write_cluster(chk, slot_cn, cbuf) != 0) {
		fat_set(chk, free_cn, EXFAT_FAT_FREE);
		chk->disk_bitmap[EXFAT_CNTOI(free_cn) / 8] &=
		    ~(1U << (EXFAT_CNTOI(free_cn) % 8));
		chk->used_bitmap[EXFAT_CNTOI(free_cn) / 8] &=
		    ~(1U << (EXFAT_CNTOI(free_cn) % 8));
		free(cbuf);
		return (EIO);
	}
	if (eod_cn != 0 && read_cluster(chk, eod_cn, cbuf) == 0 &&
	    clear_cluster_eod((union exfat_dentry *)cbuf,
	    entries_per_cluster))
		(void)write_cluster(chk, eod_cn, cbuf);
	if (was_eod && slot_idx + 3 == entries_per_cluster) {
		uint32_t next_cn;

		if (fat_get(chk, slot_cn, &next_cn) == 0)
			terminate_next_cluster(chk, next_cn, cbuf);
	}
	free(cbuf);

	/*
	 * Phase 6: Initialize LOST.DIR runtime check state.
	 */
	chk->lostdir_found = true;
	chk->lostdir_cluster = free_cn;
	chk->lostdir_dentry_cn = slot_cn;
	chk->lostdir_dentry_idx = slot_idx;
	chk->lostdir_size = chk->boot.cluster_size;
	chk->lostdir_no_fat_chain = false;
	chk->num_dirs++;
	return (0);
}

/*
 * Compare a candidate filename in LOST.DIR against an orphan's target name.
 */
static bool
lost_dir_match_name(const struct exfat_chk *chk,
    const struct exfat_dentry_name *ne, const char *name, size_t nlen)
{
	for (size_t j = 0; j < nlen; j++) {
		uint16_t c1, c2;

		c1 = le16toh(ne->ne_file_name[j]);
		c2 = (uint16_t)(unsigned char)name[j];
		if (chk->upcase_table != NULL) {
			c1 = chk->upcase_table[c1];
			c2 = chk->upcase_table[c2];
		} else {
			if (c1 >= 'a' && c1 <= 'z')
				c1 -= ('a' - 'A');
			if (c2 >= 'a' && c2 <= 'z')
				c2 -= ('a' - 'A');
		}
		if (c1 != c2)
			return (false);
	}
	return (true);
}

/*
 * Check if a file with the given name already exists in LOST.DIR.
 *
 * Traverses LOST.DIR directory entries, comparing candidate filenames
 * against existing entry sets using case-insensitive Unicode matching via
 * chk->upcase_table to prevent filename collisions during orphan reconnection.
 *
 * Returns true if the name already exists, false otherwise.
 */
static bool
lost_dir_has_name(struct exfat_chk *chk, const char *name)
{
	uint8_t *cbuf;
	union exfat_dentry *dent;
	size_t entries_per_cluster, k, nlen;
	uint32_t curr_cn, walked;
	bool found;

	if (!chk->lostdir_found ||
	    !EXFAT_CLUSTER_VALID(chk, chk->lostdir_cluster))
		return (false);

	cbuf = malloc(chk->boot.cluster_size);
	if (cbuf == NULL)
		return (false);

	nlen = strlen(name);
	entries_per_cluster = chk->boot.cluster_size /
	    sizeof(union exfat_dentry);
	curr_cn = chk->lostdir_cluster;
	found = false;
	walked = 0;

	/*
	 * Phase 1: Traverse LOST.DIR directory cluster chain.
	 */
	while (EXFAT_CLUSTER_VALID(chk, curr_cn)) {
		if (++walked > chk->boot.cluster_count)
			break;
		if (read_cluster(chk, curr_cn, cbuf) != 0)
			break;
		dent = (union exfat_dentry *)cbuf;

		/*
		 * Phase 2: Inspect 3-entry sets and perform case-insensitive
		 * name comparison.
		 */
		for (k = 0; k < entries_per_cluster; k++) {
			if (dent[k].type == EXFAT_ENTRY_EOD) {
				walked = chk->boot.cluster_count + 1;
				break;
			}
			if (dent[k].type != EXFAT_ENTRY_FILE ||
			    k + 2 >= entries_per_cluster ||
			    dent[k + 1].type != EXFAT_ENTRY_STREAM ||
			    dent[k + 2].type != EXFAT_ENTRY_NAME)
				continue;

			if (dent[k + 1].stream.se_name_length == nlen &&
			    lost_dir_match_name(chk, &dent[k + 2].name, name,
			    nlen)) {
				found = true;
				break;
			}
		}
		if (found)
			break;
		if (chk->lostdir_no_fat_chain) {
			if ((uint64_t)walked * chk->boot.cluster_size >=
			    chk->lostdir_size ||
			    EXFAT_CNTOI(curr_cn) + 1 >=
			    chk->boot.cluster_count)
				break;
			curr_cn++;
		} else if (fat_get(chk, curr_cn, &curr_cn) != 0)
			break;
	}

	free(cbuf);
	return (found);
}

/*
 * Update LOST.DIR size and stream checksum upon cluster expansion.
 *
 * When LOST.DIR allocates a new cluster to accommodate recovered orphan
 * entries, updates DataLength, ValidDataLength, clears NoFatChain flag if
 * present, recalculates SetChecksum per Spec Section 7.4.3, and writes the
 * updated directory entry set back to disk.
 *
 * Returns 0 on success, or an error code on failure.
 */
static int
update_lost_dir_size(struct exfat_chk *chk, uint64_t new_size)
{
	union exfat_dentry set[MAX_ENTRY_SET];
	union exfat_dentry *dent;
	uint8_t *cbuf;
	size_t entries_per_cluster;
	int error;
	uint8_t sec_count;

	if (!chk->lostdir_found ||
	    !EXFAT_CLUSTER_VALID(chk, chk->lostdir_dentry_cn))
		return (EINVAL);

	cbuf = malloc(chk->boot.cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	/*
	 * Phase 1: Read and validate LOST.DIR directory entry set.
	 */
	error = read_cluster(chk, chk->lostdir_dentry_cn, cbuf);
	if (error != 0) {
		free(cbuf);
		return (error);
	}

	entries_per_cluster = chk->boot.cluster_size /
	    sizeof(union exfat_dentry);
	if (chk->lostdir_dentry_idx >= entries_per_cluster) {
		free(cbuf);
		return (EINVAL);
	}

	dent = (union exfat_dentry *)cbuf;
	if (dent[chk->lostdir_dentry_idx].type != EXFAT_ENTRY_FILE) {
		free(cbuf);
		return (EINVAL);
	}

	sec_count = dent[chk->lostdir_dentry_idx].file.fe_secondary_count;
	if (sec_count < EXFAT_MIN_SECONDARY_COUNT ||
	    sec_count > EXFAT_MAX_SECONDARY_COUNT) {
		free(cbuf);
		return (EINVAL);
	}

	set[0] = dent[chk->lostdir_dentry_idx];
	if (chk->lostdir_dentry_idx + 1 + sec_count <= entries_per_cluster) {
		for (size_t s = 1; s <= sec_count; s++)
			set[s] = dent[chk->lostdir_dentry_idx + s];
	} else {
		size_t cur_avail = entries_per_cluster -
		    chk->lostdir_dentry_idx - 1;
		uint32_t next_cn;

		for (size_t s = 1; s <= cur_avail; s++)
			set[s] = dent[chk->lostdir_dentry_idx + s];

		if (fat_get(chk, chk->lostdir_dentry_cn, &next_cn) != 0)
			next_cn = EXFAT_FAT_EOF;

		read_straddled_entries(chk, next_cn, set, cur_avail,
		    sec_count, false, 0, 0);
	}

	if (set[1].type != EXFAT_ENTRY_STREAM) {
		free(cbuf);
		return (EINVAL);
	}

	/*
	 * Phase 2: Convert NoFatChain to FAT chain and update stream lengths.
	 */
	if ((set[1].stream.se_general_flags & EXFAT_FLAG_NO_FAT_CHAIN) != 0) {
		uint32_t first_cn = le32toh(set[1].stream.se_first_cluster);
		uint64_t old_size = le64toh(set[1].stream.se_data_length);
		uint32_t old_clusters = (uint32_t)((old_size /
		    chk->boot.cluster_size) +
		    ((old_size % chk->boot.cluster_size) != 0));

		for (uint32_t ci = 0; ci + 1 < old_clusters; ci++)
			fat_set(chk, first_cn + ci, first_cn + ci + 1);
		set[1].stream.se_general_flags &= ~EXFAT_FLAG_NO_FAT_CHAIN;
	}
	set[1].stream.se_data_length = htole64(new_size);
	set[1].stream.se_valid_data_length = htole64(new_size);

	/*
	 * Phase 3: Recalculate SetChecksum (Spec §7.4.3) and flush updated
	 * entry set.
	 */
	exfat_dentry_set_checksum(set, 1 + sec_count);

	error = update_dentry_set(chk, chk->lostdir_dentry_cn, dent,
	    chk->lostdir_dentry_idx, sec_count, set, cbuf,
	    entries_per_cluster, false, 0, 0);
	if (error == 0) {
		chk->lostdir_size = new_size;
		chk->lostdir_no_fat_chain = false;
	}

	free(cbuf);
	return (error);
}

/*
 * Create a directory entry set in LOST.DIR for an orphaned cluster chain.
 *
 * Generates a collision-free filename derived from the chain starting cluster
 * number (e.g., "1234" or "1234_1"), constructs a primary File Directory Entry
 * (Spec §7.4) with Stream Extension (Spec §7.6) and File Name (Spec §7.7)
 * secondary entries, and calculates the directory entry SetChecksum (Spec
 * §7.4.3).
 *
 * Scans LOST.DIR for three contiguous available entry slots, maintaining
 * End-of-Directory (EOD) markers (Spec §6.2.1) or allocating and appending a
 * new cluster when LOST.DIR is full.  Upon insertion, records the reconnected
 * clusters in the verification used bitmap.
 *
 * Returns 0 on success, ENOMEM if memory allocation fails, ENOSPC if no free
 * clusters remain for directory expansion, or EIO on I/O error.
 */
static int
insert_lost_file(struct exfat_chk *chk, uint32_t head_cn, uint64_t chain_len)
{
	union exfat_dentry *dent, set[3];
	char name[32];
	uint8_t *cbuf;
	size_t entries_per_cluster, j, k;
	uint32_t curr_cn, last_cn, walked;
	uint16_t hash;
	int error;
	uint8_t nlen;
	bool slot_found;

	/*
	 * Phase 1: Unique collision-free filename generation and NameHash
	 * calculation.
	 *
	 * Derive a base filename from the decimal head cluster number.  If a
	 * directory entry with this name already exists in LOST.DIR, append an
	 * incrementing suffix until a unique name is found.  Then calculate
	 * the 16-bit up-cased NameHash per Spec §7.6.4.
	 */
	snprintf(name, sizeof(name), "%u", head_cn);
	if (lost_dir_has_name(chk, name)) {
		unsigned int suffix = 1;

		do {
			if (head_cn > 999999999U)
				snprintf(name, sizeof(name), "%08X_%u",
				    head_cn, suffix++);
			else
				snprintf(name, sizeof(name), "%u_%u",
				    head_cn, suffix++);
		} while (suffix < 10000 && lost_dir_has_name(chk, name));
	}
	nlen = (uint8_t)strlen(name);
	if (nlen > EXFAT_CHARS_PER_NAME_ENTRY)
		nlen = EXFAT_CHARS_PER_NAME_ENTRY;

	hash = 0;
	for (j = 0; j < nlen; j++) {
		uint16_t up = chk->upcase_table[(unsigned char)name[j]];

		hash = exfat_calc_name_hash(up, hash);
	}

	/*
	 * Phase 2: Directory entry set construction and SetChecksum
	 * calculation.
	 *
	 * Construct a standard 3-entry directory entry set consisting of:
	 *   - Primary File Directory Entry (Spec §7.4, SecondaryCount = 2,
	 *     ATTR_ARCHIVE)
	 *   - Stream Extension Directory Entry (Spec §7.6, AllocPossible = 1,
	 *     NoFatChain = 0, NameLength, NameHash, FirstCluster, DataLength)
	 *   - File Name Directory Entry (Spec §7.7, Unicode UTF-16LE filename)
	 * Compute the 16-bit directory entry SetChecksum per Spec §7.4.3.
	 */
	memset(set, 0, sizeof(set));
	set[0].type = EXFAT_ENTRY_FILE;
	set[0].file.fe_secondary_count = 2;
	set[0].file.fe_file_attributes = htole16(EXFAT_ATTR_ARCHIVE);

	set[1].type = EXFAT_ENTRY_STREAM;
	set[1].stream.se_general_flags = EXFAT_FLAG_ALLOC_POSSIBLE;
	set[1].stream.se_name_length = nlen;
	set[1].stream.se_name_hash = htole16(hash);
	set[1].stream.se_first_cluster = htole32(head_cn);
	set[1].stream.se_data_length =
	    htole64(chain_len * chk->boot.cluster_size);
	set[1].stream.se_valid_data_length = set[1].stream.se_data_length;

	set[2].type = EXFAT_ENTRY_NAME;
	for (j = 0; j < nlen; j++)
		set[2].name.ne_file_name[j] = htole16((uint16_t)name[j]);

	exfat_dentry_set_checksum(set, 3);

	cbuf = malloc(chk->boot.cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	/*
	 * Phase 3: Scan LOST.DIR clusters for three contiguous available slots.
	 *
	 * Traverse the LOST.DIR cluster chain searching for an unused run of
	 * 3 slots (unallocated or EOD entries).  If an EOD entry is consumed,
	 * preserve directory termination per Spec §6.2.1 by advancing EOD.
	 * When stepping across cluster boundaries, clear interior EOD markers
	 * to prevent premature termination.
	 */
	entries_per_cluster = chk->boot.cluster_size /
	    sizeof(union exfat_dentry);
	curr_cn = chk->lostdir_cluster;
	last_cn = curr_cn;
	dent = NULL;
	slot_found = false;
	walked = 0;

	while (EXFAT_CLUSTER_VALID(chk, curr_cn)) {
		uint32_t next_cn;

		if (++walked > chk->boot.cluster_count)
			break;
		if (read_cluster(chk, curr_cn, cbuf) != 0) {
			free(cbuf);
			return (EIO);
		}
		dent = (union exfat_dentry *)cbuf;
		for (k = 0; k + 3 <= entries_per_cluster; k++) {
			bool empty = true;

			for (j = 0; j < 3; j++) {
				uint8_t t = dent[k + j].type;

				if (t == EXFAT_ENTRY_EOD)
					break;
				if ((t & EXFAT_ENTRY_TYPE_IN_USE) != 0) {
					empty = false;
					break;
				}
			}
			if (empty) {
				bool was_eod =
				    (dent[k].type == EXFAT_ENTRY_EOD ||
				    dent[k + 1].type == EXFAT_ENTRY_EOD ||
				    dent[k + 2].type == EXFAT_ENTRY_EOD);

				memcpy(&dent[k], set, sizeof(set));
				/*
				 * If an EOD marker was overwritten, terminate
				 * the directory by placing a new EOD marker at
				 * k + 3. Per Spec §6.2.1, a single EOD entry
				 * stops directory traversal, leaving all
				 * subsequent slots unallocated.
				 */
				if (was_eod && k + 3 < entries_per_cluster)
					dent[k + 3].type = EXFAT_ENTRY_EOD;
				if (write_cluster(chk, curr_cn, cbuf) != 0) {
					free(cbuf);
					return (EIO);
				}
				if (was_eod && k + 3 == entries_per_cluster) {
					if (chk->lostdir_no_fat_chain) {
						if ((uint64_t)walked *
						    chk->boot.cluster_size >=
						    chk->lostdir_size ||
						    EXFAT_CNTOI(curr_cn) + 1 >=
						    chk->boot.cluster_count)
							next_cn =
							    EXFAT_FAT_EOF;
						else
							next_cn = curr_cn + 1;
					} else if (fat_get(chk, curr_cn,
					    &next_cn) != 0)
						next_cn = EXFAT_FAT_EOF;
					terminate_next_cluster(chk, next_cn,
					    cbuf);
				}
				slot_found = true;
				break;
			}
		}
		if (slot_found)
			break;

		last_cn = curr_cn;
		if (chk->lostdir_no_fat_chain) {
			if ((uint64_t)walked * chk->boot.cluster_size >=
			    chk->lostdir_size ||
			    EXFAT_CNTOI(curr_cn) + 1 >=
			    chk->boot.cluster_count)
				next_cn = EXFAT_FAT_EOF;
			else
				next_cn = curr_cn + 1;
		} else if (fat_get(chk, curr_cn, &next_cn) != 0)
			next_cn = EXFAT_FAT_EOF;
		if (!EXFAT_CLUSTER_VALID(chk, next_cn))
			break;
		if (clear_cluster_eod(dent, entries_per_cluster) &&
		    write_cluster(chk, curr_cn, cbuf) != 0) {
			free(cbuf);
			return (EIO);
		}
		curr_cn = next_cn;
	}

	/*
	 * Phase 4: Cluster allocation and LOST.DIR directory expansion.
	 *
	 * When all existing clusters of LOST.DIR are full, search the volume
	 * allocation bitmap for an unallocated cluster (free in both disk and
	 * verification bitmaps, and not flagged bad in the FAT).  Link the new
	 * cluster into the FAT chain, initialize it with the entry set and
	 * trailing EOD marker, and update LOST.DIR size metadata.
	 */
	if (!slot_found) {
		uint32_t alloc_cn = 0;

		for (uint32_t c = 0; c < chk->boot.cluster_count; c++) {
			uint32_t idx = c / 8;
			uint8_t mask = 1U << (c % 8);
			uint32_t val;

			if (fat_get(chk, EXFAT_ITOCN(c), &val) == 0 &&
			    EXFAT_FAT_IS_BAD(val))
				continue;
			if (!(chk->disk_bitmap[idx] & mask) &&
			    !(chk->used_bitmap[idx] & mask)) {
				alloc_cn = EXFAT_ITOCN(c);
				break;
			}
		}
		if (alloc_cn == 0) {
			free(cbuf);
			return (ENOSPC);
		}

		if (dent != NULL &&
		    clear_cluster_eod(dent, entries_per_cluster) &&
		    write_cluster(chk, last_cn, cbuf) != 0) {
			free(cbuf);
			return (EIO);
		}

		memset(cbuf, 0, chk->boot.cluster_size);
		dent = (union exfat_dentry *)cbuf;
		memcpy(&dent[0], set, sizeof(set));
		if (entries_per_cluster > 3)
			dent[3].type = EXFAT_ENTRY_EOD;
		if (write_cluster(chk, alloc_cn, cbuf) != 0) {
			free(cbuf);
			return (EIO);
		}

		fat_set(chk, last_cn, alloc_cn);
		fat_set(chk, alloc_cn, EXFAT_FAT_EOF);
		chk->disk_bitmap[EXFAT_CNTOI(alloc_cn) / 8] |=
		    1U << (EXFAT_CNTOI(alloc_cn) % 8);
		chk->used_bitmap[EXFAT_CNTOI(alloc_cn) / 8] |=
		    1U << (EXFAT_CNTOI(alloc_cn) % 8);

		error = update_lost_dir_size(chk,
		    (uint64_t)(walked + 1) * chk->boot.cluster_size);
		if (error != 0) {
			free(cbuf);
			return (error);
		}
	}

	free(cbuf);

	/*
	 * Phase 5: Mark reconnected orphan clusters in verification used
	 * bitmap.
	 *
	 * Walk the reconnected orphan cluster chain and mark each cluster in
	 * chk->used_bitmap to reflect its newly assigned active allocation.
	 */
	curr_cn = head_cn;
	while (EXFAT_CLUSTER_VALID(chk, curr_cn)) {
		uint32_t idx = EXFAT_CNTOI(curr_cn) / 8;
		uint8_t mask = 1U << (EXFAT_CNTOI(curr_cn) % 8);
		uint32_t nxt;

		if ((chk->used_bitmap[idx] & mask) != 0)
			break;
		chk->used_bitmap[idx] |= mask;
		if (fat_get(chk, curr_cn, &nxt) != 0 ||
		    !EXFAT_CLUSTER_VALID(chk, nxt))
			break;
		curr_cn = nxt;
	}

	chk->num_files++;
	return (0);
}

/*
 * Reconnect orphaned cluster chains into the LOST.DIR directory.
 *
 * Scans the FAT for allocated clusters that were unreferenced during directory
 * tree traversal.  Identifies unparented chain heads, resolves cycles,
 * truncates chains at FAT EOF (Spec §4.1), and creates corresponding file
 * directory entry sets in LOST.DIR via insert_lost_file().
 *
 * Returns FSOK if no modifications were made, FSDIRMOD / FSFATMOD on repairs,
 * FSERROR if user declines or a non-fatal error occurs, or FSFATAL on failure.
 */
int
reconnect_orphans(struct exfat_chk *chk)
{
	uint8_t *has_parent, *visited;
	size_t bsize;
	uint64_t reconnected;
	uint32_t c;
	int mod;

	reconnected = 0;
	mod = FSOK;

	/*
	 * Phase 1: LOST.DIR directory discovery and creation.
	 *
	 * Ensure the LOST.DIR directory exists in the root directory,
	 * creating it if absent via create_lost_dir().
	 */
	if (!chk->lostdir_found) {
		if (!ask(1, "Create LOST.DIR"))
			return (FSERROR);
		if (create_lost_dir(chk) != 0) {
			pwarn("Failed to create LOST.DIR\n");
			return (FSERROR);
		}
		mod |= (FSDIRMOD | FSFATMOD);
	}

	bsize = howmany(chk->boot.cluster_count, 8);
	has_parent = calloc(bsize, 1);
	visited = calloc(bsize, 1);
	if (has_parent == NULL || visited == NULL) {
		free(has_parent);
		free(visited);
		perr("Out of memory during orphan reconnection");
		return (FSFATAL);
	}

	/*
	 * Phase 2: Identify child clusters in orphaned chains.
	 *
	 * Scan the FAT for unreferenced allocated clusters and record all
	 * pointed-to target clusters into the has_parent bitmap.
	 */
	for (c = 0; c < chk->boot.cluster_count; c++) {
		uint32_t cn = EXFAT_ITOCN(c);
		uint32_t idx = c / 8;
		uint8_t mask = 1U << (c % 8);
		uint32_t nxt, nval;

		if (!(chk->disk_bitmap[idx] & mask) ||
		    (chk->used_bitmap[idx] & mask))
			continue;

		if (fat_get(chk, cn, &nxt) == 0 &&
		    EXFAT_CLUSTER_VALID(chk, nxt) &&
		    (fat_get(chk, nxt, &nval) != 0 ||
		    !EXFAT_FAT_IS_BAD(nval))) {
			uint32_t n_idx = EXFAT_CNTOI(nxt) / 8;
			uint8_t n_mask = 1U << (EXFAT_CNTOI(nxt) % 8);

			if ((chk->disk_bitmap[n_idx] & n_mask) &&
			    !(chk->used_bitmap[n_idx] & n_mask))
				has_parent[n_idx] |= n_mask;
		}
	}

	/*
	 * Phase 3: Reconnect orphan cluster chains from heads.
	 *
	 * Identify chain heads (unparented orphaned clusters), traverse to
	 * EOF or cycle, terminate with EXFAT_FAT_EOF, and link into LOST.DIR
	 * via insert_lost_file().
	 */
	for (c = 0; c < chk->boot.cluster_count; c++) {
		uint32_t cn = EXFAT_ITOCN(c);
		uint32_t idx = c / 8;
		uint8_t mask = 1U << (c % 8);
		uint32_t curr, nxt, nval, prev;
		uint64_t chain_len;

		if (!(chk->disk_bitmap[idx] & mask) ||
		    (chk->used_bitmap[idx] & mask) ||
		    (has_parent[idx] & mask) ||
		    (visited[idx] & mask))
			continue;
		if (fat_get(chk, cn, &nxt) == 0 && EXFAT_FAT_IS_BAD(nxt))
			continue;

		curr = cn;
		prev = EXFAT_FAT_FREE;
		chain_len = 0;
		while (EXFAT_CLUSTER_VALID(chk, curr)) {
			uint32_t cur_idx = EXFAT_CNTOI(curr) / 8;
			uint8_t cur_mask = 1U << (EXFAT_CNTOI(curr) % 8);
			uint32_t n_idx;
			uint8_t n_mask;

			if (visited[cur_idx] & cur_mask) {
				curr = prev;
				break;
			}
			visited[cur_idx] |= cur_mask;
			chain_len++;

			if (fat_get(chk, curr, &nxt) != 0 ||
			    !EXFAT_CLUSTER_VALID(chk, nxt))
				break;
			if (fat_get(chk, nxt, &nval) == 0 &&
			    EXFAT_FAT_IS_BAD(nval))
				break;

			n_idx = EXFAT_CNTOI(nxt) / 8;
			n_mask = 1U << (EXFAT_CNTOI(nxt) % 8);
			if (!(chk->disk_bitmap[n_idx] & n_mask) ||
			    (chk->used_bitmap[n_idx] & n_mask))
				break;

			prev = curr;
			curr = nxt;
		}

		if (EXFAT_CLUSTER_VALID(chk, curr))
			fat_set(chk, curr, EXFAT_FAT_EOF);

		if (insert_lost_file(chk, cn, chain_len) == 0) {
			reconnected++;
			mod |= (FSDIRMOD | FSFATMOD);
		} else {
			pwarn("Failed to reconnect orphaned cluster chain at "
			    "%u to LOST.DIR\n", cn);
			mod |= FSERROR;
		}
	}

	/*
	 * Phase 4: Resolve residual orphaned clusters and cycles.
	 *
	 * Recover any circular or cyclic orphaned chains that lacked an
	 * unparented head cluster, reconnecting them to LOST.DIR.
	 */
	for (c = 0; c < chk->boot.cluster_count; c++) {
		uint32_t cn = EXFAT_ITOCN(c);
		uint32_t idx = c / 8;
		uint8_t mask = 1U << (c % 8);
		uint32_t curr, nxt, nval, prev;
		uint64_t chain_len;

		if (!(chk->disk_bitmap[idx] & mask) ||
		    (chk->used_bitmap[idx] & mask) ||
		    (visited[idx] & mask))
			continue;
		if (fat_get(chk, cn, &nxt) == 0 && EXFAT_FAT_IS_BAD(nxt))
			continue;

		curr = cn;
		prev = EXFAT_FAT_FREE;
		chain_len = 0;
		while (EXFAT_CLUSTER_VALID(chk, curr)) {
			uint32_t cur_idx = EXFAT_CNTOI(curr) / 8;
			uint8_t cur_mask = 1U << (EXFAT_CNTOI(curr) % 8);
			uint32_t n_idx;
			uint8_t n_mask;

			if (visited[cur_idx] & cur_mask) {
				curr = prev;
				break;
			}
			visited[cur_idx] |= cur_mask;
			chain_len++;

			if (fat_get(chk, curr, &nxt) != 0 ||
			    !EXFAT_CLUSTER_VALID(chk, nxt))
				break;
			if (fat_get(chk, nxt, &nval) == 0 &&
			    EXFAT_FAT_IS_BAD(nval))
				break;

			n_idx = EXFAT_CNTOI(nxt) / 8;
			n_mask = 1U << (EXFAT_CNTOI(nxt) % 8);
			if (!(chk->disk_bitmap[n_idx] & n_mask) ||
			    (chk->used_bitmap[n_idx] & n_mask))
				break;

			prev = curr;
			curr = nxt;
		}

		if (EXFAT_CLUSTER_VALID(chk, curr))
			fat_set(chk, curr, EXFAT_FAT_EOF);

		if (insert_lost_file(chk, cn, chain_len) == 0) {
			reconnected++;
			mod |= (FSDIRMOD | FSFATMOD);
		} else {
			pwarn("Failed to reconnect orphaned cluster chain at "
			    "%u to LOST.DIR\n", cn);
			mod |= FSERROR;
		}
	}

	free(has_parent);
	free(visited);

	pwarn("Reconnected %ju lost chain(s) to LOST.DIR\n", reconnected);
	return (mod);
}
