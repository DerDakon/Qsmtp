/** \file xtext.c
 * \brief functions for xtext parsing
 */
#include <sys/types.h>
#include "xtext.h"

ssize_t
xtextlen(const char *str)
{
	ssize_t result = 0;

	while (*str && (*str != ' ')) {
		if ((*str < '!') || (*str > '~'))
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
			str++;
			result += 3;
		} else {
			str++;
			result++;
		}
	}
	return result;
}
