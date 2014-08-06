#include <qdns.h>

#include "test_io/testcase_io.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

/*
 * temporary hack to allow freeips() to work without asserting
 *
 * This test already tests the new code path that some other library
 * functions like freeips() currently prevent from being executed
 * because not all users of struct ips have been converted yet.
 */
static void
fixup_before_free(struct ips *n)
{
	while (n != NULL) {
		n->count = 1;
		if (n->addr != &n->ad) {
			free(n->addr);
			n->addr = &n->ad;
		}
		n = n->next;
	}
}

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

static int
verify_ipv6_sorted_complete(const struct ips *ip)
{
	int err = 0;
	const struct ips *cur;

	for (cur = ip; cur->next != NULL; cur = cur->next) {

		if (cur->priority >= cur->next->priority) {
			fprintf(stderr, "priority %u comes before priority %u\n",
					cur->priority, cur->next->priority);
			err++;
		}

	}

	for (cur = ip; cur != NULL; cur = cur->next) {
		unsigned short s;
#ifdef IPV4ONLY
		int last = 1;
#else
		int last = 0;
#endif
		int has_changed = 0;

		for (s = 0; s < cur->count; s++) {
			int k = IN6_IS_ADDR_V4MAPPED(cur->addr + s);
			if (k == last)
				continue;

			last = k;
			if (has_changed) {
				fprintf(stderr, "sort order changed more than once for priority %i\n", cur->priority);
				err++;
				break;
			}
			has_changed = 1;
		}
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
			fixup_before_free(ipb);
			freeips(ipb);
			exit(ENOMEM);
		}
		memset(ipa, 0, sizeof(*ipa));

		ipa->next = ipb;
		ipb = ipa;

		ipa->addr = malloc(sizeof(*ipa->addr));
		if (ipa->addr == NULL) {
			fixup_before_free(ipb);
			freeips(ipb);
			exit(ENOMEM);
		}

		ipa->count = 1;
		ipa->addr->s6_addr32[0] = 0;
		ipa->addr->s6_addr32[1] = 0;
		ipa->addr->s6_addr32[2] = i * 1000;
		ipa->addr->s6_addr32[3] = 0;
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

	fixup_before_free(ipb);
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
			fixup_before_free(ipb);
			freeips(ipb);
			exit(ENOMEM);
		}
		ipa->next = ipb;
		ipa->name = NULL;
		ipb = ipa;

		ipa->addr = malloc(sizeof(*ipa->addr));
		if (ipa->addr == NULL) {
			fixup_before_free(ipb);
			freeips(ipb);
			exit(ENOMEM);
		}

		ipa->count = 1;
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
		ipa->priority = 42;
	}

	ipa = ipb;
	sortmx(&ipa);

	ret += verify_ipv6_sorted(ipa);

	/* sorting again should not change anything */
	sortmx(&ipa);
	ret += verify_ipv6_sorted(ipa);

	fixup_before_free(ipa);
	freeips(ipa);

	return ret;
}

/**
 * @brief check that the IPv6 addresses are sorted first for every entry
 *
 * Well, or all last in case of IPV4ONLY.
 */
static int
test_sort_ipv6_inner(void)
{
	struct ips *ipa;
	struct ips *ipb = NULL;
	int ret = 0;
	unsigned int i;
	const unsigned int count = 3;

	for (i = count; i > 0; --i) {
		unsigned short s;

		ipa = malloc(sizeof(*ipa));
		if (ipa == NULL) {
			fixup_before_free(ipb);
			freeips(ipb);
			exit(ENOMEM);
		}
		ipa->next = ipb;
		ipb = ipa;

		ipa->count = 3 + i;
		ipa->addr = malloc(ipa->count * sizeof(*ipa->addr));
		if (ipa->addr == NULL) {
			fixup_before_free(ipb);
			freeips(ipb);
			exit(ENOMEM);
		}

		for (s = 0; s < ipa->count; s++) {
			ipa->addr[s].s6_addr32[3] = i * 512 + s;
			/* make this v4mapped or not */
			ipa->addr[s].s6_addr32[1] = 0;
			if ((i + s) % 2 == 0) {
				ipa->addr[s].s6_addr32[2] = 0;
				ipa->addr[s].s6_addr32[0] = htonl(0xfe800000);
			} else {
				ipa->addr[s].s6_addr32[2] = htonl(0xffff);
				ipa->addr[s].s6_addr32[0] = 0;
			}
		}
		ipa->priority = i;
		ipa->name = NULL;
	}

	ipa = ipb;
	sortmx(&ipa);

	ret += verify_ipv6_sorted_complete(ipa);

	/* sorting again should not change anything */
	sortmx(&ipa);
	ret += verify_ipv6_sorted_complete(ipa);

	fixup_before_free(ipa);
	freeips(ipa);

	return ret;
}

int
main(void)
{
	int err = 0;

	err += test_sort_priority();
	err += test_sort_ipv6();
	err += test_sort_ipv6_inner();

	return err;
}
