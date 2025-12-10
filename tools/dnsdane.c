/** \file dnsdane.c
 \brief tool to query the DNS TLSA record for a given host

 \details This uses the exact same code that Qremote uses to check the TLSA record.
 It should give the same result as `host -t TLSA _25._tcp.HOSTNAME` with only formatting
 differences.
 */

#include <qdns_dane.h>

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
	if (argc == 1) {
		fprintf(stderr, "Usage: %s name [name ...]\n", argv[0]);
		return 1;
	}

	for (int i = 1; i < argc; i++) {
		struct daneinfo *info;

		printf("querying: %s\n", argv[i]);
		fflush(stdout);

		int j = dnstlsa(argv[i], 25, &info);
		if (j < 0) {
			printf("failed\n");
			continue;
		}

		if (j == 0) {
			printf("no entry\n");
			continue;
		}

		for (int k = 0; k < j; k++) {
			printf("record %i: %u %u %u ", k, info[k].cert_usage, info[k].selector, info[k].matching_type);

			for (size_t l = 0; l < info[k].datalen; l++)
				printf("%02X", info[k].data[l]);
			printf("\n");
		}

		daneinfo_free(info, j);

	}

	return 0;
}
