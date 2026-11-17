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

#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <errno.h>
#include <stdbool.h>
#endif

#include <fs/exfat/exfat_ondisk.h>
#include <fs/exfat/exfat_unicode.h>

/*
 * Decompress an on-disk exFAT Up-case table into a flat 65,536-entry array per
 * Specification §7.2.
 *
 * Initializes table with default identity mappings (table[i] = i).  Parses the
 * compressed byte stream raw of length raw_len: an escape code of 0xFFFF
 * (EXFAT_UPCASE_COMPRESSED_FLAG) is followed by a 16-bit count of characters to
 * skip (retaining identity mappings), while any other 16-bit value assigns the
 * explicit uppercase character code for the current character index.  In Table
 * 25 (the recommended compressed up-case table per Spec §7.2), the final
 * character 0xFFFF (U+FFFF) is recorded as a literal 0xFFFF value at the end of
 * the stream without a subsequent skip count.
 *
 * Returns 0 on success, or EINVAL if raw_len is invalid, the stream is
 * truncated, an escape count is invalid, or the stream fails to define all
 * 65,536 characters.
 */
int
exfat_decompress_upcase(const uint8_t *raw, size_t raw_len, uint16_t *table)
{
	uint32_t i;
	size_t offset;
	uint32_t ch;

	if (raw == NULL || table == NULL || (raw_len & 1) != 0 ||
	    raw_len == 0 || raw_len > EXFAT_MAX_UPCASE_SIZE)
		return (EINVAL);

	/* Initialize flat table with identity mappings */
	for (i = 0; i < EXFAT_UPCASE_TABLE_CHARS; i++)
		table[i] = (uint16_t)i;

	offset = 0;
	ch = 0;

	while (offset + sizeof(uint16_t) <= raw_len &&
	    ch < EXFAT_UPCASE_TABLE_CHARS) {
		uint16_t val = le16dec(&raw[offset]);
		offset += sizeof(uint16_t);

		if (val == EXFAT_UPCASE_COMPRESSED_FLAG) {
			uint16_t count;

			/*
			 * In the Microsoft recommended compressed up-case table
			 * (Spec §7.2 Table 25), the final entry maps character
			 * 0xFFFF (U+FFFF) to itself as a literal 0xFFFF value
			 * at the end of the stream without a trailing skip
			 * count.
			 */
			if (offset + sizeof(uint16_t) > raw_len) {
				if (ch == EXFAT_UPCASE_TABLE_CHARS - 1) {
					table[ch] = val;
					ch++;
					break;
				}
				return (EINVAL);
			}
			count = le16dec(&raw[offset]);
			offset += sizeof(uint16_t);

			if (count == 0 ||
			    ch + count > EXFAT_UPCASE_TABLE_CHARS)
				return (EINVAL);
			ch += count;
		} else {
			table[ch] = val;
			ch++;
		}
	}

	if (ch != EXFAT_UPCASE_TABLE_CHARS || offset != raw_len)
		return (EINVAL);

	return (0);
}

/*
 * Convert an array of UTF-16 code units to a null-terminated UTF-8 string.
 *
 * Decodes up to nchars UTF-16 code units from src into destination buffer dst
 * of size dstlen bytes.  Correctly decodes surrogate pairs into 4-byte UTF-8
 * sequences, and emits the Unicode replacement character (U+FFFD) for unpaired
 * surrogates.  Guarantees null-termination when dstlen > 0.
 */
void
exfat_utf16_to_utf8(const uint16_t *src, size_t nchars, char *dst,
    size_t dstlen)
{
	size_t si, di = 0;

	if (dstlen == 0)
		return;

	for (si = 0; si < nchars; si++) {
		uint16_t c = src[si];

		if (c == 0)
			break;
		if (c < 0x80) {
			if (di + 1 >= dstlen)
				break;
			dst[di++] = (char)c;
		} else if (c < 0x800) {
			if (di + 2 >= dstlen)
				break;
			dst[di++] = (char)(0xC0 | (c >> 6));
			dst[di++] = (char)(0x80 | (c & 0x3F));
		} else if (c >= 0xD800 && c <= 0xDFFF) {
			if (c <= 0xDBFF && si + 1 < nchars) {
				uint16_t c2 = src[si + 1];

				if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
					uint32_t cp;

					if (di + 4 >= dstlen)
						break;
					cp = 0x10000 +
					    (((uint32_t)(c - 0xD800) << 10) |
					    (c2 - 0xDC00));
					dst[di++] = (char)(0xF0 | (cp >> 18));
					dst[di++] = (char)(0x80 |
					    ((cp >> 12) & 0x3F));
					dst[di++] = (char)(0x80 |
					    ((cp >> 6) & 0x3F));
					dst[di++] = (char)(0x80 | (cp & 0x3F));
					si++;
					continue;
				}
			}
			/* Unpaired surrogate: emit U+FFFD replacement char */
			if (di + 3 >= dstlen)
				break;
			dst[di++] = (char)0xEF;
			dst[di++] = (char)0xBF;
			dst[di++] = (char)0xBD;
		} else {
			if (di + 3 >= dstlen)
				break;
			dst[di++] = (char)(0xE0 | (c >> 12));
			dst[di++] = (char)(0x80 | ((c >> 6) & 0x3F));
			dst[di++] = (char)(0x80 | (c & 0x3F));
		}
	}
	dst[di] = '\0';
}

/*
 * Convert a UTF-8 string to an array of UTF-16 code units.
 *
 * Validates and decodes srclen bytes of UTF-8 data from src, checking for
 * overlong encodings, invalid continuation bytes, and illegal surrogate
 * ranges.  Encodes Unicode scalar values into dst (up to max_dst_chars code
 * units), generating surrogate pairs for codepoints above 0xFFFF.
 *
 * Stores the number of UTF-16 code units written in *out_nchars.
 * Returns 0 on success, EINVAL if src contains invalid UTF-8, or
 * ENAMETOOLONG if the converted string exceeds max_dst_chars.
 */
int
exfat_utf8_to_utf16(const char *src, size_t srclen, uint16_t *dst,
    size_t max_dst_chars, size_t *out_nchars)
{
	size_t si = 0, di = 0;

	while (si < srclen && di < max_dst_chars) {
		uint8_t c0 = (uint8_t)src[si++];

		if ((c0 & 0x80) == 0)
			/* 1-byte ASCII (0x00 - 0x7F) */
			dst[di++] = c0;
		else if ((c0 & 0xE0) == 0xC0) {
			/* 2-byte sequence (0x80 - 0x7FF) */
			uint16_t cp;
			uint8_t c1;

			if (si >= srclen)
				return (EINVAL);
			c1 = (uint8_t)src[si++];
			if ((c1 & 0xC0) != 0x80)
				return (EINVAL);
			cp = ((c0 & 0x1F) << 6) | (c1 & 0x3F);
			if (cp < 0x80)
				return (EINVAL);
			dst[di++] = cp;
		} else if ((c0 & 0xF0) == 0xE0) {
			/* 3-byte sequence (0x800 - 0xFFFF) */
			uint16_t cp;
			uint8_t c1, c2;

			if (si + 1 >= srclen)
				return (EINVAL);
			c1 = (uint8_t)src[si++];
			c2 = (uint8_t)src[si++];
			if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80)
				return (EINVAL);
			cp = ((c0 & 0x0F) << 12) |
			    ((c1 & 0x3F) << 6) | (c2 & 0x3F);
			if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))
				return (EINVAL);
			dst[di++] = cp;
		} else if ((c0 & 0xF8) == 0xF0) {
			/* 4-byte sequence (surrogate pair) */
			uint32_t cp;
			uint8_t c1, c2, c3;

			if (si + 2 >= srclen)
				return (EINVAL);
			c1 = (uint8_t)src[si++];
			c2 = (uint8_t)src[si++];
			c3 = (uint8_t)src[si++];
			if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 ||
			    (c3 & 0xC0) != 0x80)
				return (EINVAL);
			cp = ((c0 & 0x07) << 18) |
			    ((c1 & 0x3F) << 12) |
			    ((c2 & 0x3F) << 6) | (c3 & 0x3F);
			if (cp < 0x10000 || cp > 0x10FFFF)
				return (EINVAL);
			cp -= 0x10000;
			if (di + 2 > max_dst_chars)
				return (ENAMETOOLONG);
			dst[di++] = 0xD800 + (cp >> 10);
			dst[di++] = 0xDC00 + (cp & 0x3FF);
		} else
			return (EINVAL);
	}

	if (si < srclen)
		return (ENAMETOOLONG);

	*out_nchars = di;
	return (0);
}

/*
 * Validate filename characters per exFAT Specification §7.7.3.
 *
 * Inspects nchars UTF-16 characters in name.  Rejects names of length zero,
 * characters in the range 0x0000 to 0x001F, forbidden characters (", *, /, :,
 * <, >, ?, \, |), and names consisting exclusively of space characters
 * (0x0020).
 *
 * Returns true if the filename conforms to the specification, false otherwise.
 */
bool
exfat_is_valid_name(const uint16_t *name, size_t nchars)
{
	size_t i;
	bool has_non_space = false;

	if (nchars == 0)
		return (false);

	for (i = 0; i < nchars; i++) {
		uint16_t c = name[i];

		if (c < 0x0020)
			return (false);
		if (c != 0x0020)
			has_non_space = true;
		switch (c) {
		case '"':
		case '*':
		case '/':
		case ':':
		case '<':
		case '>':
		case '?':
		case '\\':
		case '|':
			return (false);
		default:
			break;
		}
	}
	return (has_non_space);
}

/*
 * Validate volume label characters per exFAT Specification §7.3.3.
 *
 * Inspects nchars UTF-16 characters in label.  Allows empty labels (nchars ==
 * 0), enforces the maximum length bound EXFAT_MAX_VOLUME_LABEL_CHARS (11
 * characters), and rejects characters in the range 0x0000 to 0x001F and
 * forbidden characters (", *, /, :, <, >, ?, \, |).
 *
 * Returns true if the label conforms to the specification, false otherwise.
 */
bool
exfat_is_valid_label(const uint16_t *label, size_t nchars)
{
	if (nchars == 0)
		return (true);
	if (nchars > EXFAT_MAX_VOLUME_LABEL_CHARS)
		return (false);

	for (size_t i = 0; i < nchars; i++) {
		uint16_t c = label[i];

		if (c < 0x0020)
			return (false);
		switch (c) {
		case '"':
		case '*':
		case '/':
		case ':':
		case '<':
		case '>':
		case '?':
		case '\\':
		case '|':
			return (false);
		default:
			break;
		}
	}
	return (true);
}
