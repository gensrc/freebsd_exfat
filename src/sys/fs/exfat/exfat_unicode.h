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

#ifndef _FS_EXFAT_EXFAT_UNICODE_H_
#define _FS_EXFAT_EXFAT_UNICODE_H_

#include <sys/param.h>

#ifdef _KERNEL
#include <fs/exfat/exfat_vfsops.h>

/*
 * Convert a UTF-16 character to uppercase using the mount's up-case table,
 * falling back to ASCII uppercase if the table is not available.
 */
static inline uint16_t
exfat_upcase_char(const struct exfat_mount *pmp, uint16_t ch)
{
	if (__predict_true(pmp != NULL && pmp->pm_upcase != NULL))
		return (pmp->pm_upcase[ch]);

	if (ch >= 'a' && ch <= 'z')
		return (ch - ('a' - 'A'));
	return (ch);
}
#else
#include <stdbool.h>
#endif /* _KERNEL */

int	exfat_decompress_upcase(const uint8_t *raw, size_t raw_len,
	    uint16_t *table);
void	exfat_utf16_to_utf8(const uint16_t *src, size_t nchars, char *dst,
	    size_t dstlen);
int	exfat_utf8_to_utf16(const char *src, size_t srclen, uint16_t *dst,
	    size_t max_dst_chars, size_t *out_nchars);
bool	exfat_is_valid_name(const uint16_t *name, size_t nchars);
bool	exfat_is_valid_label(const uint16_t *label, size_t nchars);

#endif /* _FS_EXFAT_EXFAT_UNICODE_H_ */
