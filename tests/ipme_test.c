#include <ipme.h>
#include <qdns.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *testips[] = {
	"::ffff:127.0.0.1",	/* IPv4 localhost, you must have it */
	"::ffff:10.255.255.255", /* broadcast in private network, valid but can't be configured if you are sane */
	"::1",	/* IPv6 broadcast, you must have it unless IPV4ONLY is defined */
	"ff01::1", /* IPv6 broadcast, valid but can't be configured if you are sane */
	"::ffff:0.0.0.0", /* localhost, localnet */
	"::ffff:127.4.5.6" /* anything in 127/8 is localhost */
};

/**
 * Test with the given list of IPs
 *
 * @param inidx indexes to set up initially
 * @param outidx IP addresses that should remain
 *
 * Both lists are indexes into testips and are terminated by -1.
 */
static int
run_test(const int *inidx, const int *outidx)
{
	struct ips *in = NULL;
	struct ips *res;
	unsigned int idx;

	for (idx = 0; inidx[idx] != -1; idx++) {
		struct ips *a = malloc(sizeof(*a));

		if (a == NULL)
			exit(ENOMEM);

		memset(a, 0, sizeof(*a));
		a->addr = &a->ad;

		inet_pton(AF_INET6, testips[inidx[idx]], a->addr);
		if (in == NULL) {
			in = a;
			res = a;
		} else {
			res->next = a;
			res = a;
		}
	}

	res = filter_my_ips(in);
	if (outidx == NULL) {
		struct ips *tmp = res;

		if (res == NULL)
			return 0;

		idx = 0;
		while (tmp != NULL) {
			tmp = tmp->next;
			idx++;
		}

		fprintf(stderr, "expected no output, but got %u addresses\nInput was: ", idx);

		for (idx = 0; inidx[idx] != -1; idx++)
			fprintf(stderr, "%s ", testips[inidx[idx]]);
		fprintf(stderr, "\n");

		freeips(res);

		return 1;
	} else {
		struct ips *tmp = res;
		idx = 0;

		while (tmp != NULL) {
			struct in6_addr addr;

			if (outidx[idx] == -1) {
				fprintf(stderr, "expected %u output items, but got more\n", idx);
				freeips(res);
				return 1;
			}

			inet_pton(AF_INET6, testips[outidx[idx]], &addr);

			if (!IN6_ARE_ADDR_EQUAL(&addr, tmp->addr)) {
				char astr[INET6_ADDRSTRLEN];

				inet_ntop(AF_INET6, tmp->addr, astr, sizeof(astr));

				fprintf(stderr, "expected %s at output index %u, but got %s\n",
						testips[outidx[idx]], idx, astr);
				freeips(res);
				return 1;
			}

			tmp = tmp->next;
			idx++;
		}

		if (outidx[idx] != -1) {
			fprintf(stderr, "got %u output items, expected more\nInput was: ", idx);

			for (idx = 0; inidx[idx] != -1; idx++)
				fprintf(stderr, "%s ", testips[inidx[idx]]);
			fprintf(stderr, "\n");

			freeips(res);
			return 1;
		}
	}

	freeips(res);

	return 0;
}

int
main(void)
{
	const int only_localhost[] = { 0, -1 };
	const int only_localhost_dupes[] = { 0, 0, 0, -1 };
	const int only_ipv4_in1[] = { 0, 1, -1 };
	const int only_ipv4_in2[] = { 0, 1, -1 };
	const int only_ipv4_in3[] = { 0, 0, 1, 0, -1 };
	const int only_ipv4_in4[] = { 1, 0, -1 };
	const int only_ipv4_in5[] = { 1, 0, 0, -1 };
	const int only_ipv4_out[] = { 1, -1 };
	const int only_ipv4_dupes_in[] = { 0, 1, 0, 1, 1, -1 };
	const int only_ipv4_dupes_out[] = { 1, 1, 1, -1 };
	const int only_ipv4_loopback_net[] = { 0, 5, -1 };
	const int only_ipv4_anynet[] = { 4, -1 };
#ifndef IPV4ONLY
	const int only_localhost_ipv6[] = { 2, -1 };
	const int only_localhost_dupes_ipv6[] = { 2, 2, 2, -1 };
	const int only_localhost_mixed[] = { 0, 2, -1 };
	const int only_localhost_dupes_mixed[] = { 2, 0, 0, 2, 2, 0, -1 };
	const int only_ipv6_in1[] = { 2, 3, -1 };
	const int only_ipv6_in2[] = { 2, 3, -1 };
	const int only_ipv6_in3[] = { 2, 2, 3, 2, -1 };
	const int only_ipv6_in4[] = { 3, 2, -1 };
	const int only_ipv6_in5[] = { 3, 2, 2, 2, -1 };
	const int only_ipv6_out[] = { 3, -1 };
	const int only_ipv6_dupes_in[] = { 2, 3, 2, 3, 3, -1 };
	const int only_ipv6_dupes_out[] = { 3, 3, 3, -1 };
	const int mixed_in1[] = { 0, 1, 2, 3, -1 };
	const int mixed_in2[] = { 1, 0, 3, 2, -1 };
	const int mixed_out1[] = { 1, 3, -1 };
	const int mixed_in3[] = { 1, 0, 1, 3, 2, 3, 0, -1 };
	const int mixed_out2[] = { 1, 1, 3, 3, -1 };
#endif /* IPV4ONLY */
	int ret = 0;

	ret += run_test(only_localhost, NULL);
	ret += run_test(only_localhost_dupes, NULL);
	ret += run_test(only_ipv4_in1, only_ipv4_out);
	ret += run_test(only_ipv4_in2, only_ipv4_out);
	ret += run_test(only_ipv4_in3, only_ipv4_out);
	ret += run_test(only_ipv4_in4, only_ipv4_out);
	ret += run_test(only_ipv4_in5, only_ipv4_out);
	ret += run_test(only_ipv4_dupes_in, only_ipv4_dupes_out);
	ret += run_test(only_ipv4_loopback_net, NULL);
	ret += run_test(only_ipv4_anynet, NULL);

#ifndef IPV4ONLY
	ret += run_test(only_localhost_ipv6, NULL);
	ret += run_test(only_localhost_dupes_ipv6, NULL);
	ret += run_test(only_localhost_mixed, NULL);
	ret += run_test(only_localhost_dupes_mixed, NULL);
	ret += run_test(only_ipv6_in1, only_ipv6_out);
	ret += run_test(only_ipv6_in2, only_ipv6_out);
	ret += run_test(only_ipv6_in3, only_ipv6_out);
	ret += run_test(only_ipv6_in4, only_ipv6_out);
	ret += run_test(only_ipv6_in5, only_ipv6_out);
	ret += run_test(only_ipv6_dupes_in, only_ipv6_dupes_out);
	ret += run_test(mixed_in1, mixed_out1);
	ret += run_test(mixed_in2, mixed_out1);
	ret += run_test(mixed_in3, mixed_out2);
#endif /* IPV4ONLY */

	return ret;
}
