/** \file xtext_test.c
 \brief xtext testcases
 */

#include <qsmtpd/xtext.h>
#include "test_io/testcase_io.h"

#include <stdio.h>

static const char *valid_strings[] = {
	"",		/* no xtext is always valid */
	"<>",		/* explicitely permitted */
	"foobar@example.com",	/* xtext as valid addr-spec */
	"+3C+3E",	/* <> has hexdigit */
	NULL
};

static const char *invalid_strings[] = {
	"+A",                   /* hexdigit with second char missing */
	"+aF",                  /* hexdigit is defined as all uppercase */
	"a=b@example.com",      /* = is not permitted */
	"\rfoobar@example.com",	/* control characters are not permitted */
	"f\244@example.com",	/* only ASCII is permitted */
	"foobar@@example.com",	/* invalid addrspec */
	"valid567890123456789012345678901234567889012345678901234567890@"
		"tooooo.long.a123456789.b123456789.c123456789.d12345789.e123456789.f12345678"
		"tooooo.long.a123456789.b123456789.c123456789.d12345789.e123456789.f12345678"
		"tooooo.long.a123456789.b123456789.c123456789.d12345789.e123456789.f12345678"
		"tooooo.long.a123456789.b123456789.c123456789.d12345789.e123456789.com",
	NULL
};

int main(void)
{
	int errcnt = 0;

	for (unsigned int i = 0; valid_strings[i] != NULL; i++)
		if (xtextlen(valid_strings[i]) < 0) {
			fputs("Error: valid string \"", stdout);
			fputs(valid_strings[i], stdout);
			puts("\" not accepted");
			errcnt++;
		}

	for (unsigned int i = 0; invalid_strings[i] != NULL; i++)
		if (xtextlen(invalid_strings[i]) >= 0) {
			fputs("Error: invalid string \"", stdout);
			fputs(invalid_strings[i], stdout);
			puts("\" not rejected");
			errcnt++;
		}

	return (errcnt != 0) ? 1 : 0;
}
