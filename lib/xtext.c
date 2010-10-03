/** \file xtext.c
 * \brief functions for xtext parsing
 */
#include "xtext.h"

#include "qdns.h"

#include <sys/types.h>
#include <string.h>

static unsigned char
hexchar(const char ch)
{
	if (ch > '9')
		return ch - 'A' + 10;
	else
		return ch - '0';
}

static char
hexdigit(const char *str)
{
	return hexchar(*str) * 16 + hexchar(*(str + 1));
}

/**
 * get the length of xtext string
 *
 * @param str string to parse
 * @return length of xtext
 * @retval -1 string is invalid
 *
 * @see RfC 2554
 */
ssize_t
xtextlen(const char *str)
{
	ssize_t result = 0;
	char addrspec[64 + 1 + 255 + 1];	/* localpart @ domain \0 */
	size_t idx = 0;

	while (*str && (*str != ' ')) {
		if ((*str < '!') || (*str > '~'))
			return -1;
		/* maximum length */
		if (idx > sizeof(addrspec) - 2)
			return -1;
		if (*str == '+') {
			str++;
			if (!(((*str >= '0') && (*str <= '9')) ||
					((*str >= 'A') && (*str <= 'F'))))
				return -1;
			str++;
			if (!(((*str >= '0') && (*str <= '9')) ||
					((*str >= 'A') && (*str <= 'F'))))
				return -1;

			addrspec[idx++] = hexdigit(str - 1);

			str++;
			result += 3;
		} else if ((*str >= 0x21) && (*str <= 0x7e) && (*str != 0x3d)) {
			addrspec[idx++] = *str++;
			result++;
		} else {
			return -1;
		}
	}

	if (idx != 0) {
		addrspec[idx] = '\0';
		if (strcmp(addrspec, "<>") == 0)
			return result;

		if (!addrspec_valid(addrspec))
				return -1;
	}

	return result;
}
