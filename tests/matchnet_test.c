/** \file matchnet_test.c
 \brief IP address with netmask testcases
 */

#include "antispam.h"
#include "match.h"
#include "qsmtpd.h"
#include "test_io/testcase_io.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

struct xmitstat xmitstat;

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

	for (i = 127; i >= 1; --i) {
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

	if (ip6_matchnet(&s1, &s2, 0) != 1) {
		char maskstr[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, &s2, maskstr, sizeof(maskstr));
		printf("Error: IPv6 address %s match with %s/0 does not return 1\n", ipstr, maskstr);
		err++;
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

	for (i = 32; i >= 1; --i) {
		if (ip4_matchnet(&s1, &s2, i) != expect) {
			char maskstr[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET, &s2, maskstr, sizeof(maskstr));
			printf("Error: IPv4 address %s match with %s/%i does not return expected result\n", ipstr, maskstr, i);
			err++;
		}
		s2.s_addr &= htonl(~mask);
		mask <<= 1;
	}

	if (ip4_matchnet(&s1, &s2, 0) != 1) {
		char maskstr[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET, &s2, maskstr, sizeof(maskstr));
		printf("Error: IPv4 address %s match with %s/0 does not return 1\n", ipstr, maskstr);
		err++;
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

static int
matchdomain_test()
{
	int err = 0;
	const char testhost[] = "test.example.net";
	const char *goodpatterns[] = {
		testhost,
		".example.net",
		".net",
		NULL
	};
	const char *badpatterns[] = {
		"another.test.example.net",
		"example.net",
		".example.org",
		".xample.net",
		NULL
	};
	unsigned int i = 0;

	while (goodpatterns[i] != NULL) {
		if (!matchdomain(testhost, strlen(testhost), goodpatterns[i])) {
			fprintf(stderr, "%s did not match %s\n", goodpatterns[i], testhost);
			err++;
		}
		i++;
	}

	i = 0;
	while (badpatterns[i] != NULL) {
		if (matchdomain(testhost, strlen(testhost), badpatterns[i])) {
			fprintf(stderr, "%s matched %s\n", badpatterns[i], testhost);
			err++;
		}
		i++;
	}

	/* now check all bad patterns at once, shouldn't make any difference */
	if (domainmatch(testhost, strlen(testhost), badpatterns) != 0) {
		fprintf(stderr, "domainmatch() should have returned 0, but returned 1\n");
		err++;
	}

	return err;
}

int dnstxt(char **out __attribute__ ((unused)), const char *host __attribute__ ((unused)))
{
	return 0;
}

int main(void)
{
	int errcnt = 0;

	if (ip4_test())
		errcnt++;

	if (ip6_test())
		errcnt++;

	if (matchdomain_test())
		errcnt++;

	return (errcnt != 0) ? 1 : 0;
}
