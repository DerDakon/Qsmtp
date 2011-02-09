/** \file spf_test.c
 \brief SPF testcases
 */
#include "qdns.h"
#include "test_io/testcase_io.h"

#include <stdlib.h>
#include <stdio.h>

static const char *valid_names[] = {
	"a.de", /* shortest valid name */
	"very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.looooong.example.org", /* 255 characters, maximum allowed */
	"veryloooooooooooooooooooooooooooooooooooooooooooooooooooooooong.sub.example.org",
	"something.stupid3.example.com",
	NULL
};

static const char *invalid_names[] = {
	"a.a", /* top level domain too short */
	"aaaa.a", /* top level domain too short */
	"toooolooooooooooooooooooooooooooooooooooooooooooooooooooooooooong.sub.example.org", /* subpart has more than 63 characters */
	"second.toooolooooooooooooooooooooooooooooooooooooooooooooooooooooooooong.sub.example.org", /* subpart has more than 63 characters */
	"toooo.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.looooong.example.org", /* more than 255 characters */
	"under_score.is.not.allowed.example.net",
	"spaces are not permitted.foo.bar",
	".must.not.start.with.dot",
	"no,comma.com",
	"foo",
	"foo.com2",
	NULL
};

static int
test_fqdn_valid(void)
{
	int err = 0;
	unsigned int idx = 0;

	while (valid_names[idx] != NULL) {
		if (domainvalid(valid_names[idx]) != 0) {
			fputs("Error: ", stdout);
			fputs(valid_names[idx], stdout);
			puts(" incorrectly marked as invalid");
			err++;
		}
		idx++;
	}

	idx = 0;
	while (invalid_names[idx] != NULL) {
		if (domainvalid(invalid_names[idx]) == 0) {
			fputs("Error: ", stdout);
			fputs(invalid_names[idx], stdout);
			puts(" incorrectly marked as valid");
			err++;
		}
		idx++;
	}

	return err;
}

int main(void)
{
	int err = 0;

	err += test_fqdn_valid();

	return err ? 1 : 0;
}
