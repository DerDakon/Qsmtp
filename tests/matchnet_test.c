/** \file matchnet_test.c
 \brief IP address with netmask testcases
 */

#include <match.h>
#include <qsmtpd/antispam.h>
#include <qsmtpd/qsmtpd.h>
#include "test_io/testcase_io.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct xmitstat xmitstat;

void
dieerror(int a __attribute__ ((unused)))
{
	abort();
}

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
	struct in6_addr s1;
	int err = 0;
	const char s1str[] = "fe80::1234:6789:50ab:cdef";
	const char s2str[] = "2001::1234:6789:50ab:cdef";

	err = inet_pton(AF_INET6, s1str, &s1);
	assert(err == 1);
	err = 0;

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
	struct in_addr s2;
	unsigned char i;
	int err;
	uint32_t mask = 1;

	err = inet_pton(AF_INET, matchstr, &s2);
	assert(err == 1);

	err = 0;

	for (i = 32; i >= 1; --i) {
		if (ip4_matchnet(&xmitstat.sremoteip, &s2, i) != expect) {
			char maskstr[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET, &s2, maskstr, sizeof(maskstr));
			printf("Error: IPv4 address %s match with %s/%i does not return expected result\n", ipstr, maskstr, i);
			err++;
		}
		s2.s_addr &= htonl(~mask);
		mask <<= 1;
	}

	if (ip4_matchnet(&xmitstat.sremoteip, &s2, 0) != 1) {
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
	const char s2str[] = "10.0.2.61";
	int err = 0;
	char fnbuf[22] = "ip4_matchnet_XXXXXX";
	int fd;
	struct in_addr ip4;
	int i;
	char ch;

	memset(&xmitstat, 0, sizeof(xmitstat));
	xmitstat.ipv4conn = 1;
	i = inet_pton(AF_INET6, ipstr, &xmitstat.sremoteip);
	assert(i == 1);

	err += ip4_match_test(ipstr, s1str, 1);
	err += ip4_match_test(ipstr, s2str, 0);

	fd = mkstemp(fnbuf);
	if (fd == -1) {
		fprintf(stderr, "can not open temporary file\n");
		return ++err;
	}

	i = inet_pton(AF_INET, s2str, &ip4);
	assert(i == 1);

	/* Test an empty file. Should simply return "no match". */
	i = lookupipbl(fd);
	if (i != 0) {
		fprintf(stderr, "lookupipbl() with empty file should return 0 but returned %i\n", i);
		err++;
	}

	fd = open(fnbuf, O_APPEND | O_RDWR | O_CLOEXEC, 0600);
	if (fd == -1) {
		fprintf(stderr, "can not open temporary file\n");
		return ++err;
	}

	/* write 5 times the same IP with different netmasks.
	 * None of them should match. */
	for (i = 0; i < 5; i++) {
		ch = 8 + 2 * i;
		write(fd, &ip4, sizeof(ip4));
		write(fd, &ch, 1);
	}
	/* file size is now 25 byte */

	i = lookupipbl(fd);
	if (i != 0) {
		fprintf(stderr, "lookupipbl() without matching nets should return 0 but returned %i\n", i);
		err++;
	}

	fd = open(fnbuf, O_APPEND | O_RDWR | O_CLOEXEC, 0600);
	if (fd == -1) {
		fprintf(stderr, "can not open temporary file\n");
		return ++err;
	}
	/* create a file that has invalid length */
	write(fd, &ip4, sizeof(ip4));
	/* file size is now 29 byte */
	i = lookupipbl(fd);
	if (i != -1) {
		fprintf(stderr, "lookupipbl() with file of invalid size should have returned -1 but returned %i\n", i);
		err++;
	}

	fd = open(fnbuf, O_APPEND | O_RDWR | O_CLOEXEC, 0600);
	if (fd == -1) {
		fprintf(stderr, "can not open temporary file\n");
		return ++err;
	}
	/* write an invalid netmask */
	ch = 42;
	write(fd, &ch, 1);
	/* file size is now 30 byte */
	i = lookupipbl(fd);
	if (i != -1) {
		fprintf(stderr, "lookupipbl() with file containing invalid netmask should have returned -1 but returned %i\n", i);
		err++;
	}
	fd = open(fnbuf, O_RDWR | O_CLOEXEC, 0600);
	if (fd == -1) {
		fprintf(stderr, "can not open temporary file\n");
		return ++err;
	}
	if (lseek(fd, -1, SEEK_END) == -1) {
		close(fd);
		fprintf(stderr, "can not seek in temporary file\n");
		return ++err;
	}

	ch = 24;
	write(fd, &ch, 1);
	i = inet_pton(AF_INET, s1str, &ip4);
	assert(i);
	write(fd, &ip4, sizeof(ip4));
	write(fd, &ch, 1);
	/* file size is now 35 byte */

	i = lookupipbl(fd);
	if (i <= 0) {
		fprintf(stderr, "lookupipbl() with valid file with match should return greater 0 but returned %i\n", i);
		err++;
	}

	/* test IPv6 connection, file now has invalid size for IPv6 */
	xmitstat.ipv4conn = 0;
	fd = open(fnbuf, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		fprintf(stderr, "can not open temporary file\n");
		return ++err;
	}
	i = lookupipbl(fd);
	if (i != -1) {
		fprintf(stderr, "lookupipbl() with file of invalid size for IPv6 should have returned -1 but returned %i\n", i);
		err++;
	}

	unlink(fnbuf);

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
	const char *mixedpatterns[] = {
		badpatterns[1],
		badpatterns[0],
		goodpatterns[1],
		badpatterns[2],
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

	if (domainmatch(testhost, strlen(testhost), goodpatterns) != 1) {
		fprintf(stderr, "domainmatch() should have returned 1, but returned 0\n");
		err++;
	}

	if (domainmatch(testhost, strlen(testhost), mixedpatterns) != 1) {
		fprintf(stderr, "domainmatch() should have returned 1, but returned 0\n");
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

	umask(S_IWGRP | S_IWOTH);

	if (ip4_test())
		errcnt++;

	if (ip6_test())
		errcnt++;

	if (matchdomain_test())
		errcnt++;

	/* Now ignore the log calls. Until now they were an error,
	 * now lookupipbl() should complain about not being able to lock. */
	testcase_ignore_log_writen();
	if (lookupipbl(-1) != -1) {
		fprintf(stderr, "lookupipbl(-1) should return an error\n");
		errcnt++;
	} else if (errno != ENOLCK) {
		fprintf(stderr, "lookupipbl(-1) should set errno to ENOLCK\n");
		errcnt++;
	}

	return (errcnt != 0) ? 1 : 0;
}
