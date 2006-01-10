#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "base64.h"
#include "sstring.h"

int main(int argc, char *argv[])
{
	string clear;
	size_t i;

	if (argc == 1)
		return 1;

	b64decode(argv[1], strlen(argv[1]), &clear);
	for (i = 0; i < clear.len; i++) {
		if (!clear.s[i]) {
			write(1, "\\0", 2);
		} else {
			write(1, clear.s + i, 1);
		}
	}
	write(1, "\n", 1);
	return 0;
}
