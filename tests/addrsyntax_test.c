#include "qdns.h"
#include "sstring.h"
#include "test_io/testcase_io.h"

#include <stdio.h>
#include <string.h>
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
	"me@[127.0.0.1]",
	"me@[IPv6:::1]",
	"me@[IPv6:ffe::ffff:0123]",
	"toolonglocalpart12345678901234567890123456789012345678901234567890@example.com",	/* localpart >64 chars */
	NULL
};

const char *invalid[] = {
	"fo.\nbar@example.com",		/* unquoted control character */
	"foo@bar..example.com",		/* double dot in domainpart */
	"\"f\\oo\"@bar.example.com",	/* invalid quoting */
	"\"\noo\"@example.com",		/* invalid quoted control character */
	"\"foo@example.com",		/* unterminated quote */
	"me@[127.0.0.256]",		/* invalid IPv4 address */
	"me@[IPv6:::abcd:fg:0:8:9]",	/* invalid IPv6 address (invalid hex character 'g') */
	"me@[IPv6:::abcd::1234:2]",	/* invalid IPv6 address (multiple ::) */
	"me@[::1]",			/* valid IPv6 address without IPv6: prefix */
	"me@[IPv6:::1",			/* missing closing bracket */
	"me@[IPv6:::1].com",		/* text after closing bracket */
	"me@[IPv6:abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd]",	/* too long IPv6 string */
	"me@[127.128.129.140.2]",	/* too long IPv4 string */
	NULL
};

/* not valid as email address, but as filter expression */
const char *validparts[] = {
	"foo.example.com",		/* only domain */
	"@foo.example.com",		/* missing localpart */
	NULL
};

struct {
	const char *in;
	int flags;
	const char *addr;
	const char *more;
	int retval;
} syntaxpatterns[] = {
	/* postmaster is only valid for flags == 1 */
	{
		.in = "postmaster>",
		.flags = 0,
		.addr = "",
		.more = "",
		.retval = 0
	},
	{
		.in = "postmaster>",
		.flags = 1,
		.addr = "postmaster",
		.more = "",
		.retval = 1
	},
	/* postmaster is only valid for flags == 1 */
	{
		.in = "postmaster>",
		.flags = 2,
		.addr = "",
		.more = "",
		.retval = 0
	},
	{
		.in = ">",
		.flags = 0,
		.addr = "",
		.more = "",
		.retval = 1
	},
	/* empty address is only valid for flags == 0 */
	{
		.in = ">",
		.flags = 1,
		.addr = "",
		.more = "",
		.retval = 0
	},
	/* empty address is only valid for flags == 0 */
	{
		.in = ">",
		.flags = 2,
		.addr = "",
		.more = "",
		.retval = 0
	},
	/* an ordinary address */
	{
		.in = "foo@bar.example.com>",
		.flags = 0,
		.addr = "foo@bar.example.com",
		.more = "",
		.retval = 3
	},
	/* an ordinary address with following text*/
	{
		.in = "foo@bar.example.com> text beyond",
		.flags = 0,
		.addr = "foo@bar.example.com",
		.more = " text beyond",
		.retval = 3
	},
	{
		.in = NULL
	}
};

static int 
addrsyntax_test(void)
{
	int err = 0;
	int i = 0;

	while (syntaxpatterns[i].in != NULL) {
		char inbuf[512];
		string outaddr;
		char *more = NULL;

		STREMPTY(outaddr);
		strcpy(inbuf, syntaxpatterns[i].in);

		printf("Testing '%s' with flags %i\n", syntaxpatterns[i].in, syntaxpatterns[i].flags);

		if (addrsyntax(inbuf, syntaxpatterns[i].flags, &outaddr, &more) != syntaxpatterns[i].retval) {
			fprintf(stderr, "ERROR: did not return %i\n", syntaxpatterns[i].retval);
			err++;
			i++;
			continue;
		}

		if ((outaddr.len != strlen(syntaxpatterns[i].addr)) ||
				((outaddr.s != NULL) && (strcmp(outaddr.s, syntaxpatterns[i].addr) != 0))) {
			fprintf (stderr, "ERROR: did not return address %s, but %s (lenght %lu)\n",
					syntaxpatterns[i].addr, outaddr.s, (unsigned long)outaddr.len);
			err++;
		} else if ((more != NULL) && (syntaxpatterns[i].more) && strcmp(more, syntaxpatterns[i].more) != 0) {
			fprintf (stderr, "ERROR: returned 'more' as %s instead of %s\n",
					more, syntaxpatterns[i].more);
			err++;
		}

		free(outaddr.s);

		i++;
	}

	return err;
}

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

	i = 0;
	while (validparts[i] != NULL) {
		fputs("testing valid address part: ", stdout);
		puts(validparts[i]);
		if (checkaddr(validparts[i]) != 0) {
			err++;
			fputs("checkaddr() rejected valid filter expression: ", stderr);
			fputs(validparts[i], stderr);
			fputs("\n", stderr);
		}

		if (addrspec_valid(validparts[i])) {
			err++;
			fputs("addrspec_valid() did not reject invalid address: ", stderr);
			fputs(validparts[i], stderr);
			fputs("\n", stderr);
		}

		i++;
	}

	err += addrsyntax_test();

	return err;
}
