#include <qdns.h>

#include "test_io/testcase_io.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static int
verify(const struct ips *ip)
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

static int
verify_ipv6_sorted(const struct ips *ip)
{
	int err = verify(ip);

	if (IN6_IS_ADDR_V4MAPPED(ip->addr)) {
		fputs("v4 mapped address comes first\n", stderr);
		return ++err;
	}

	if (!IN6_IS_ADDR_V4MAPPED(ip->next->addr)) {
		fputs("second position is no IPv4 mapped address\n", stderr);
		return ++err;
	}

	if (!IN6_IS_ADDR_V4MAPPED(ip->next->next->addr)) {
		fputs("third position is no IPv4 mapped address\n", stderr);
		return ++err;
	}

	return err;
}

/**
 * @brief check that sorting by priority works
 */
static int
test_sort_priority(void)
{
	struct ips *ipa;
	struct ips *ipb = NULL;
	int ret = 0;
	unsigned int i;
	const unsigned int count = 3;

	for (i = count; i > 0; --i) {
		ipa = malloc(sizeof(*ipa));
		if (ipa == NULL) {
			freeips(ipb);
			exit(ENOMEM);
		}
		memset(ipa, 0, sizeof(*ipa));
		ipa->addr = &ipa->ad;
		ipa->addr->s6_addr32[2] = i * 1000;
		ipa->next = ipb;
		ipb = ipa;
	}

	for (i = 2 << (count + 1); i > 0; --i) {
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

		ret += verify(ipa);
		ipb = ipa;
	}

	freeips(ipb);

	return ret;
}

/**
 * @brief check that for 2 IPs with the same priority the IPv6 one is preferred
 */
static int
test_sort_ipv6(void)
{
	struct ips *ipa;
	struct ips *ipb = NULL;
	int ret = 0;
	unsigned int i;
	const unsigned int count = 3;

	for (i = count; i > 0; --i) {
		ipa = malloc(sizeof(*ipa));
		if (ipa == NULL) {
			freeips(ipb);
			exit(ENOMEM);
		}
		ipa->addr = &ipa->ad;
		ipa->addr->s6_addr32[3] = i * 1000;
		/* make this v4mapped or not */
		ipa->addr->s6_addr32[1] = 0;
		if (i == count) {
			ipa->addr->s6_addr32[2] = 0;
			ipa->addr->s6_addr32[0] = htonl(0xfe800000);
		} else {
			ipa->addr->s6_addr32[2] = htonl(0xffff);
			ipa->addr->s6_addr32[0] = 0;
		}
		ipa->next = ipb;
		ipa->priority = 42;
		ipa->name = NULL;
		ipb = ipa;
	}

	ipa = ipb;
	sortmx(&ipa);

	ret += verify_ipv6_sorted(ipa);

	/* sorting again should not change anything */
	sortmx(&ipa);
	ret += verify_ipv6_sorted(ipa);

	freeips(ipa);

	return ret;
}

int
main(void)
{
	int err = 0;

	err += test_sort_priority();
	err += test_sort_ipv6();

	return err;
}
