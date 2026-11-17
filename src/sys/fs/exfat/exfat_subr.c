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
#include <sys/systm.h>
#include <sys/clock.h>

#include <fs/exfat/exfat_ondisk.h>
#include <fs/exfat/exfat_subr.h>
#include <fs/exfat/exfat_unicode.h>
#include <fs/exfat/exfat_vfsops.h>

/*
 * Compute the 16-bit exFAT NameHash for a UTF-16 filename per Specification
 * §7.6.4.
 *
 * Case-folds each UTF-16 character in name using the volume's active up-case
 * table (exfat_upcase_char()), and accumulates the hash using the standard
 * circular rotate-and-add algorithm (exfat_calc_name_hash()).
 *
 * Returns the computed 16-bit NameHash.
 */
uint16_t
exfat_name_hash(const struct exfat_mount *pmp, const uint16_t *name,
    size_t nchars)
{
	uint16_t hash = 0;

	for (size_t i = 0; i < nchars; i++) {
		uint16_t uch;

		uch = exfat_upcase_char(pmp, name[i]);
		hash = exfat_calc_name_hash(uch, hash);
	}
	return (hash);
}

/*
 * Compare two UTF-16 strings case-insensitively using the volume's active
 * up-case table per Specification §7.2 and §7.7.
 *
 * Compares up to nchars characters between s1 and s2 after converting each
 * character to upper case via exfat_upcase_char().
 *
 * Returns true if all nchars case-folded characters match, false otherwise
 * or if either pointer is NULL.
 */
bool
exfat_case_compare(const struct exfat_mount *pmp, const uint16_t *s1,
    const uint16_t *s2, size_t nchars)
{
	if (s1 == NULL || s2 == NULL)
		return (false);

	for (size_t i = 0; i < nchars; i++) {
		if (s1[i] == s2[i])
			continue;
		if (exfat_upcase_char(pmp, s1[i]) !=
		    exfat_upcase_char(pmp, s2[i]))
			return (false);
	}
	return (true);
}

/*
 * Sanity validation bounds for converting to/from struct timespec based on
 * real-world civil time zones on Earth (UTC-12:00 to UTC+14:00 in 15-minute
 * intervals).
 */
#define EXFAT_TZ_MIN	(-48)	/* UTC-12:00 in 15-min intervals */
#define EXFAT_TZ_MAX	56	/* UTC+14:00 in 15-min intervals */

/*
 * Encode host system UTC timezone offset into exFAT 8-bit timezone format
 * per Specification §7.4.10.
 *
 * Queries utc_offset() and converts the seconds offset into 15-minute
 * intervals.  Clamps the result to valid civil timezone boundaries
 * [EXFAT_TZ_MIN, EXFAT_TZ_MAX] (UTC-12:00 to UTC+14:00), masks to 7 bits,
 * and sets the EXFAT_TZ_VALID (0x80) flag.
 *
 * Returns the encoded 8-bit timezone byte.
 */
uint8_t
exfat_tz_offset(void)
{
	int offset_sec;
	int intervals;

	offset_sec = -utc_offset();
	intervals = offset_sec / (15 * 60);
	/*
	 * Per exFAT Spec §7.4.10.1, OffsetFromUtc is a 7-bit signed integer
	 * representing 15-minute intervals in the range [-56, +56] (UTC-14:00
	 * to UTC+14:00). Gracefully clamp the host timezone offset to this
	 * valid range to prevent integer overflow into the 7-bit signed field
	 * or generating invalid out-of-range offsets on non-standard systems.
	 */
	if (intervals < EXFAT_TZ_MIN)
		intervals = EXFAT_TZ_MIN;
	else if (intervals > EXFAT_TZ_MAX)
		intervals = EXFAT_TZ_MAX;
	return (EXFAT_TZ_VALID | (uint8_t)(intervals & EXFAT_TZ_OFFSET_MASK));
}

/*
 * Decode packed MS-DOS timestamp, 10ms increment, and exFAT timezone offset
 * into a UNIX struct timespec per Specification §7.4.5–§7.4.10.
 *
 * Unpacks the 32-bit ftime into date and time components and hun (10ms
 * sub-second ticks).  If tz has EXFAT_TZ_VALID (0x80) set and falls within
 * valid civil timezone bounds [EXFAT_TZ_MIN, EXFAT_TZ_MAX], sign-extends the
 * 7-bit intervals and shifts tv_sec to convert from local timestamp to UTC.
 * If tz is invalid or out of range, decodes as unadjusted local time.
 *
 * Stores the converted timestamp in *tsp.
 */
void
exfat_fattime2timespec(uint32_t ftime, uint8_t hun, uint8_t tz,
    struct timespec *tsp)
{
	uint16_t date = ftime >> 16;
	uint16_t time = ftime & 0xFFFF;

	if ((tz & EXFAT_TZ_VALID) != 0) {
		int8_t intervals = (int8_t)(tz & EXFAT_TZ_OFFSET_MASK);

		if ((intervals & 0x40) != 0)
			intervals |= (int8_t)0x80;
		if (intervals >= EXFAT_TZ_MIN && intervals <= EXFAT_TZ_MAX) {
			fattime2timespec(date, time, hun, 1, tsp);
			tsp->tv_sec -= (time_t)intervals * (15 * 60);
			return;
		}
	}
	fattime2timespec(date, time, hun, 0, tsp);
}
