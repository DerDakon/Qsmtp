/** \file clearpass.c
 * \brief decode a base64 encoded password
 */

#include <base64.h>
#include <sstring.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	string clear;

	if (argc == 1)
		return 1;

	int err = b64decode(argv[1], strlen(argv[1]), &clear);
	if (err != 0)
		return err;

	for (size_t i = 0; i < clear.len; i++) {
		if (!clear.s[i]) {
			write(1, "\\0", 2);
		} else {
			write(1, clear.s + i, 1);
		}
	}
	write(1, "\n", 1);
	return 0;
}
