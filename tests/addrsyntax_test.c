#include "qdns.h"

#include <stdio.h>
#include <unistd.h>

const char *valid[] = {
	"foo@example.com",
	"foo+bar@example.com",
	"foo-bar@example.com",
	"foo~bar@example.com",
	"foo~#bar@example.com",
	"\"foo\"@bar.example.com",
	"\"f\\\"oo\"@bar.example.com",
	"\"f\\\\oo\"@bar.example.com",
	NULL
};

const char *invalid[] = {
	"fo.\nbar@example.com",
	"foo@bar..example.com",
	"\"f\\oo\"@bar.example.com",
	NULL
};

int
main(void)
{
	unsigned int i;
	int err = 0;

	i = 0;
	while (valid[i] != NULL) {
		fputs("testing valid address: ", stdout);
		puts(valid[i]);
		if (checkaddr(valid[i]) != 0) {
			err++;
			fputs("checkaddr() rejected valid address: ", stderr);
			fputs(valid[i], stderr);
			fputs("\n", stderr);
		}

		if (!addrspec_valid(valid[i])) {
			err++;
			fputs("addrspec_valid() rejected valid address: ", stderr);
			fputs(valid[i], stderr);
			fputs("\n", stderr);
		}

		i++;
	}

	i = 0;
	while (invalid[i] != NULL) {
		fputs("testing invalid address: ", stdout);
		puts(invalid[i]);
		if (checkaddr(invalid[i]) == 0) {
			err++;
			fputs("checkaddr() did not reject invalid address: ", stderr);
			fputs(invalid[i], stderr);
			fputs("\n", stderr);
		}

		if (addrspec_valid(invalid[i])) {
			err++;
			fputs("addrspec_valid() did not reject invalid address: ", stderr);
			fputs(invalid[i], stderr);
			fputs("\n", stderr);
		}

		i++;
	}

	return err;
}
