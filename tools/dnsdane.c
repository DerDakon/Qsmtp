#include <qdns_dane.h>

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
	int i;

	if (argc == 1) {
		fprintf(stderr, "Usage: %s name [name ...]\n", argv[0]);
		return 1;
	}

	for (i = 1; i < argc; i++) {
		struct daneinfo *info;
		int j, k;

		printf("querying: %s\n", argv[i]);
		fflush(stdout);

		j = dnstlsa(argv[i], 25, &info);
		if (j < 0) {
			printf("failed\n");
			continue;
		}

		if (j == 0) {
			printf("no entry\n");
			continue;
		}

		for (k = 0; k < j; k++) {
			unsigned int l;
			printf("record %i: %u %u %u ", k, info[k].cert_usage, info[k].selectors, info[k].matching_types);

			for (l = 0; l < sizeof(info[0].data) / sizeof(info[0].data[0]); l++)
				printf("%08X", ntohl(info[k].data[l]));
		}

		free(info);

		printf("\n");
	}

	return 0;
}
