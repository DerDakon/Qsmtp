/** \file fmt.c
 \brief functions for output formatting
 */

#include <fmt.h>

/**
 * print unsigned long into a given buffer
 *
 * @param u number to convert
 * @param res pointer to memory where result is stored, should be ULSTRLEN bytes long
 */
void
ultostr(const unsigned long u, char *res)
{
	int j = 1;
	unsigned long v = u;

	while (v /= 10) {
		j++;
	}

	res[j] = '\0';
	v = u;
	do {
		res[--j] = '0' + v % 10;
		v /= 10;
	} while (j);
}
