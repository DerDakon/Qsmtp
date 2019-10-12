/** \file utf8.c
 \brief UTF-8 processing functions
 */

#include <qutf8.h>

#include <stdbool.h>

/*
 * RfC 3629
 *
   UTF8-char   = UTF8-1 / UTF8-2 / UTF8-3 / UTF8-4
   UTF8-1      = %x00-7F
   UTF8-2      = %xC2-DF UTF8-tail
   UTF8-3      = %xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) /
                 %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )
   UTF8-4      = %xF0 %x90-BF 2( UTF8-tail ) / %xF1-F3 3( UTF8-tail ) /
                 %xF4 %x80-8F 2( UTF8-tail )
   UTF8-tail   = %x80-BF
*/

static bool
utf8_tail(unsigned char c)
{
	return (c >= 0x80) && (c <= 0xbf);
}

/**
 * @brief check if this is the beginning of an UTF8-2 sequence
 * @returns the number of UTF8-tail bytes expected)
 * @retval 0 this is no UTF8-4 sequence
 */
static int
utf8_2_start(unsigned char c)
{
	return ((c >= 0xc2) && (c <= 0xdf)) ? 1 : 0;
}

/**
 * @brief check if this is the beginning of an UTF8-3 sequence
 * @returns the number of UTF8-tail bytes expected)
 * @retval 0 this is no UTF8-3 sequence
 */
static int
utf8_3_start(unsigned char ch1, unsigned char ch2)
{
	if ((ch1 & 0xf0) != 0xe0)
		return 0;

	int u3_type = ch1 & 0x0f;

	if (u3_type == 0) {
		if ((ch2 >= 0xa0) && (ch2 <=0xbf))
			return 1;
	} else if (u3_type == 0xd) {
		if ((ch2 >= 0x80) && (ch2 <= 0x9f))
			return 1;
	} else {
		/* 2 UTF8-tail byte follow, the first one is ch2 */
		if (utf8_tail(ch2))
			return 1;
	}

	return 0;
}

/**
 * @brief check if this is the beginning of an UTF8-4 sequence
 * @returns the number of UTF8-tail bytes expected)
 * @retval 0 this is no UTF8-4 sequence
 */
static int
utf8_4_start(unsigned char ch1, unsigned char ch2)
{
	switch (ch1) {
	case 0xf0:
		if ((ch2 > 0x90) && (ch2 <= 0xbf))
			return 2;
		else
			return 0;
	case 0xf1:
	case 0xf2:
	case 0xf3:
		return 3;
	case 0xf4:
		if ((ch2 > 0x80) && (ch2 <= 0x8f))
			return 2;
		else
			return 0;
	default:
		return 0;
	}
}

/**
 * @brief check if a given string contains only valid UTF-8 sequences
 *
 * @param s string to check
 * @returns the number of UTF-8 characters in s
 * @retval -1 the sequence is invalid
 */
int
valid_utf8(const cstring s)
{
	int cnt = 0;
	int tails = 0;

	for (size_t i = 0; i < s.len; i++) {
		unsigned char c = s.s[i];

		if (tails > 0) {
			if (utf8_tail(c)) {
				tails--;
				continue;
			}
			return -1;
		}

		if (c <= 0x7f) {
			cnt++;
			continue;
		}

		tails = utf8_2_start(c);
		if (tails > 0) {
			cnt++;
			continue;
		}

		if (i >= s.len - 2)
			return -1;

		unsigned char cnext = s.s[i + 1];
		i++; /* both functions will already handle both bytes */

		tails = utf8_3_start(c, cnext);
		if (tails > 0) {
			cnt++;
			continue;
		}

		tails = utf8_4_start(c, cnext);
		if (tails > 0) {
			cnt++;
			continue;
		}

		return -1;
	}

	if (tails > 0)
		return -1;

	return cnt;
}
