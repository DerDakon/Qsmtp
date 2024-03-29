/** \file dnstxt.c
 \brief tool to query the DNS TXT record for a given host

 \details This uses the exact same code that Qremote uses to check the TXT record.
 It should give the same result as `host -t TXT HOSTNAME` with only formatting
 differences.
 */

#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libowfatconn.h>

int
main(int argc, char **argv)
{
	char *out = NULL;
	int r;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s domain\n", argv[0]);
		return 1;
	}

	r = dnstxt_records(&out, argv[1]);
	if (r < 0)
		return 2;

	const char *o = out;
	for (int i = 0; i < r; i++) {
		printf("result: %s\n", o);
		o += strlen(o) + 1;
	}

	free(out);

	return 0;
}
