/** \file matchnet_test.c
 \brief IP address with netmask testcases
 */

#include "match.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static int
ip6_test_match(const char *ipstr, const char *matchstr, const int expect)
{
	struct in6_addr s1, s2;
	unsigned char i;
	int err;
	uint32_t mask = 1;

	err = inet_pton(AF_INET6, ipstr, &s1);
	assert(err == 1);
	err = inet_pton(AF_INET6, matchstr, &s2);
	assert(err == 1);

	err = 0;

	for (i = 127; i >= 30; --i) {
		if ((i % 32) != 0) {
			s2.s6_addr32[i / 32] &= htonl(~mask);
			mask <<= 1;
		} else {
			s2.s6_addr32[i / 32] = 0;
			mask = 1;
		}

		if (ip6_matchnet(&s1, &s2, i) != expect) {
			char maskstr[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET6, &s2, maskstr, sizeof(maskstr));
			printf("Error: IPv6 address %s match with %s/%i does not return expected result\n", ipstr, maskstr, i);
			err++;
		}
	}

	return err;
}

static int
ip6_test(void)
{
	struct in6_addr s1, s2;
	int err = 0;
	const char s1str[] = "fe80::1234:6789:50ab:cdef";
	const char s2str[] = "2001::1234:6789:50ab:cdef";

	err = inet_pton(AF_INET6, s1str, &s1);
	assert(err == 1);
	err = 0;
	s2 = s1;

	if (ip6_matchnet(&s1, &s1, 128) != 1) {
		printf("Error: IPv6 address %s does not match itself\n", s1str);
		err++;
	}

	err += ip6_test_match(s1str, s1str, 1);
	err += ip6_test_match(s1str, s2str, 0);

	return err;
}

static int
ip4_match_test(const char *ipstr, const char *matchstr, const int expect)
{
	struct in6_addr s1;
	struct in_addr s2;
	unsigned char i;
	int err;
	uint32_t mask = 1;

	err = inet_pton(AF_INET6, ipstr, &s1);
	assert(err == 1);
	err = inet_pton(AF_INET, matchstr, &s2);
	assert(err == 1);

	err = 0;

	for (i = 32; i >= 8; --i) {
		if (ip4_matchnet(&s1, &s2, i) != expect) {
			char maskstr[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET, &s2, maskstr, sizeof(maskstr));
			printf("Error: IPv4 address %s match with %s/%i does not return expected result\n", ipstr, maskstr, i);
			err++;
		}
		s2.s_addr &= htonl(~mask);
		mask <<= 1;
	}

	return err;
}

static int
ip4_test(void)
{
	const char ipstr[] ="::ffff:172.17.42.253";
	const char s1str[] = "172.17.42.253";
	const char s2str[] = "62.27.20.61";
	int err = 0;

	err += ip4_match_test(ipstr, s1str, 1);
	err += ip4_match_test(ipstr, s2str, 0);

	return err;
}


int main(void)
{
	int errcnt = 0;

	if (ip4_test())
		errcnt++;

	if (ip6_test())
		errcnt++;

	return (errcnt != 0) ? 1 : 0;
}