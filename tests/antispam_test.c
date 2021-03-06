#include <qsmtpd/antispam.h>

#include <qsmtpd/qsmtpd.h>
#include "test_io/testcase_io.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct xmitstat xmitstat;

void
dieerror(int a __attribute__ ((unused)))
{
	abort();
}

static unsigned int logcount;

static const char **dnsentries;

static int
check_nomatch(const int r, const char *msg)
{
	int err = 0;

	if (r != -1) {
		fprintf(stderr, "%s returned %i instead of -1\n", msg, r);
		err++;
	} else if (errno != 0) {
		fprintf(stderr, "%s did not set errno to 0\n", msg);
		err++;
	}

	return err;
}

static int
test_rbl()
{
	int err = 0;
	char * const rbls[] = {
		"foo.bar.example.com",
		"foo.timeout.example.com",
		"bar.foo.example.com",
		"foo.foo.example.com",
		"bar.bar.example.com",
		"the-name-of-this.rbl-is-sooooooooooooooooooooooooooooooooooooooooo.looooooooooooooooooooooooooooooooooooong"
			".loooooooooooooooooooooong.looooooooooooooooooooooooooooooooooooooong."
			"that-it-will-overflow-when-used-with-ipv6-addresses.example.com",
		NULL
	};
	const char *ips[] = {
		"::ffff:10.0.0.1",
		"::ffff:10.0.0.2",
		"::ffff:172.18.42.42",
#ifdef IPV4ONLY
		"::ffff:172.30.17.18",
#else
		"4242:cafe::1",
#endif
		NULL
	};
	const char *entries[4];

	for (unsigned int ipidx = 0; ips[ipidx] != NULL; ipidx++) {
		char *txt = NULL;
		int r;

		if (inet_pton(AF_INET6, ips[ipidx], &xmitstat.sremoteip) != 1) {
			fprintf(stderr, "can not parse %s as IPv6 address\n", ips[ipidx]);
			exit(EINVAL);
		}

		xmitstat.ipv4conn = IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip) ? 1 : 0;

		errno = EINVAL;
		dnsentries = NULL;
		r = check_rbl(rbls, &txt);
		err += check_nomatch(r, "check_rbl() without DNS entries");
		free(txt);
		txt = NULL;

		entries[0] = "2.0.0.10.foo.timeout.example.com";
		entries[1] = NULL;
		dnsentries = entries;

		r = check_rbl(rbls, &txt);
		free(txt);
		txt = NULL;
		if (ipidx == 1) {
			if ((r != -1) || (errno != EAGAIN)) {
				fprintf(stderr, "check_rbl() should have returned timeout but returned %i for ip %s\n", r, ips[ipidx]);
				err++;
			}
		} else {
			err += check_nomatch(r, "check_rbl() without matching DNS entries");
		}

		entries[0] = "42.42.18.172.bar.example.com";
		r = check_rbl(rbls, &txt);
		free(txt);
		txt = NULL;
		err += check_nomatch(r, "check_rbl() without matching DNS entries");

		entries[0] = "42.42.18.172.bar.bar.example.com";
		r = check_rbl(rbls, &txt);
		free(txt);
		txt = NULL;
		if (ipidx == 2) {
			if (r != 4) {
				fprintf(stderr, "check_rbl() should have returned 4 but returned %i for ip %s\n", r, ips[ipidx]);
				err++;
			}
			/* do the same test again, but this time skip the TXT lookup */
			r = check_rbl(rbls, NULL);
			if (r != 4) {
				fprintf(stderr, "check_rbl(x, NULL) should have returned 4 but returned %i for ip %s\n", r, ips[ipidx]);
				err++;
			}
		} else {
			err += check_nomatch(r, "check_rbl() without matching DNS entries");
		}

		/* One DNSBL returns timeout, but a later one matches. Should still return match. */
		entries[0] = "4.2.4.2.foo.bar.example.com";
#ifdef IPV4ONLY
		entries[1] = "18.17.30.172.foo.timeout.example.com";
		entries[2] = "18.17.30.172.bar.foo.example.com";
#else
		entries[1] = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.a.c.2.4.2.4.foo.timeout.example.com";
		entries[2] = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.a.c.2.4.2.4.bar.foo.example.com";
#endif
		entries[3] = NULL;
		r = check_rbl(rbls, &txt);
		free(txt);
		txt = NULL;
		if (ipidx == 3) {
			if (r != 2) {
				fprintf(stderr, "check_rbl() should have returned 2 but returned %i for ip %s\n", r, ips[ipidx]);
				err++;
			}
		} else {
			err += check_nomatch(r, "check_rbl() without matching DNS entries");
		}
	}

	/* 4 tests per loop, one IPv6 address: 4 messages */
	const unsigned int expected_logs =
#ifdef IPV4ONLY
			0;
#else
			4;
#endif
	if (logcount != expected_logs) {
		fprintf(stderr, "log functions were called %i times but only 4 were expected\n", logcount);
		err++;
	}

	return err;
}

void test_log_writen(int priority __attribute__ ((unused)), const char **msg)
{
	static int firstseen;

	if (!firstseen) {
		firstseen = 1;
		printf("the messages about too long DNSBLs are expected and part of the test\n");
	}

	for (unsigned int i = 0; msg[i] != NULL; i++)
		printf("%s", msg[i]);
	printf("\n");
	logcount++;
}

int
test_ask_dnsa(const char *a, struct in6_addr **b)
{
	if (dnsentries == NULL)
		return 0;

	if (b != NULL)
		*b = NULL;

	for (unsigned int i = 0; dnsentries[i] != NULL; i++) {
		if (strcmp(dnsentries[i], a) == 0) {
			/* found a match, now use the rbl name to get the result */
			if (strstr(a, "timeout") != NULL)
				return DNS_ERROR_TEMP;
			return 1;
		}
	}

	return 0;
}

int
dnstxt(char **a, const char *b)
{
	if (b == NULL)
		return -1;

	*a = NULL;
	return 0;
}

int
main(void)
{
	int err = 0;

	testcase_setup_log_writen(test_log_writen);
	testcase_setup_ask_dnsa(test_ask_dnsa);

	err += test_rbl();

	return err;
}
