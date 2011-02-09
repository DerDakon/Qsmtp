#include "qdns.h"
#include "test_io/testcase_io.h"

#include <stdio.h>
#include <string.h>

static int
verify(struct ips *ip)
{
	int err = 0;

	if (ip->next == NULL) {
		fputs("next pointer not set on first entry\n", stderr);
		return ++err;
	}

	if (ip->next->next == NULL) {
		fputs("next pointer not set on second entry\n", stderr);
		return ++err;
	}

	if (ip->next->next->next != NULL) {
		fputs("next pointer set on third entry\n", stderr);
		return ++err;
	}

	if (ip->priority > ip->next->priority) {
		fputs("first entry has higher priority than second\n", stderr);
		err++;
	}

	if (ip->next->priority > ip->next->next->priority) {
		fputs("second entry has higher priority than third\n", stderr);
		err++;
	}

	return err;
}

int
main(void)
{
	struct ips *ipa, *ipb;
	unsigned int i;
	int err = 0;

	ipb = NULL;

	for (i = 3; i > 0; --i) {
		ipa = malloc(sizeof(*ipa));
		memset(ipa, 0, sizeof(*ipa));
		ipa->addr.s6_addr32[2] = i * 1000;
		ipa->next = ipb;
		ipb = ipa;
	}

	for (i = 16; i > 0; --i) {
		unsigned int k = 0;

		ipa = ipb;
		while (ipa != NULL) {
			/* shuffling around the number so we get any permutation
			 * of ordering in input */
			ipa->priority = ((i & (1 << (2 - k))) ?
							(17 + 3 * k) :
							((k * 3 + i) * 13)) % 43;
			ipa = ipa->next;
			k++;
		}

		ipa = ipb;
		sortmx(&ipa);

		err += verify(ipa);
		ipb = ipa;
	}

	freeips(ipb);

	return err;
}
