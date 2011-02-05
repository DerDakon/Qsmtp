#include "antispam.h"
#include "qsmtpd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct xmitstat xmitstat;

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
		"bar.foo.example.com",
		"foo.foo.example.com",
		"bar.bar.example.com",
		"foo.timeout.example.com",
		NULL
	};
	const char *ips[] = {
		"::ffff:10.0.0.1",
		"::ffff:10.0.0.2",
		"::ffff:172.18.42.42",
		"4242:cafe::1",
		NULL
	};
	const char *entries[2];
	unsigned int ipidx = 0;

	for (ipidx = 0; ips[ipidx] != NULL; ipidx++) {
		char *txt = NULL;
		int r;

		if (inet_pton(AF_INET6, ips[ipidx], &xmitstat.sremoteip) != 1) {
			fprintf(stderr, "can not parse %s as IPv6 address\n", ips[ipidx]);
			exit(EINVAL);
		}

		xmitstat.ipv4conn = IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip) ? 1 : 0;

		errno = EINVAL;
		r = check_rbl(NULL, &txt); 
		free(txt);
		txt = NULL;
		err += check_nomatch(r, "check_rbl(NULL, txt)");

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
		err += check_nomatch(r, "check_rbl() without matching DNS entries");

		entries[0] = "42.42.18.172.bar.bar.example.com";
		r = check_rbl(rbls, &txt);
		free(txt);
		txt = NULL;
		if (ipidx == 2) {
			if (r != 3) {
				fprintf(stderr, "check_rbl() should have returned 3 but returned %i for ip %s\n", r, ips[ipidx]);
				err++;
			}
		} else {
			err += check_nomatch(r, "check_rbl() without matching DNS entries");
		}

		entries[0] = "4.2.4.2.foo.bar.example.com";
		entries[1] = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.a.c.2.4.2.4.bar.foo.example.com";
		entries[2] = NULL;
		r = check_rbl(rbls, &txt);
		free(txt);
		txt = NULL;
		if (ipidx == 3) {
			if (r != 1) {
				fprintf(stderr, "check_rbl() should have returned 1 but returned %i for ip %s\n", r, ips[ipidx]);
				err++;
			}
		} else {
			err += check_nomatch(r, "check_rbl() without matching DNS entries");
		}
	}

	if (logcount != 0)
		err++;

	return err;
}

int
main(void)
{
	int err = 0;

	err += test_rbl();

	return err;
}


void log_writen(int priority __attribute__ ((unused)), const char **msg __attribute__ ((unused)))
{
	logcount++;
}

void log_write(int priority __attribute__ ((unused)), const char *msg __attribute__ ((unused)))
{
}

int data_pending(void)
{
	return 1;
}

int
ask_dnsa(const char *a, struct ips **b)
{
	unsigned int i;

	if (dnsentries == NULL)
		return 1;

	if (b != NULL)
		*b = NULL;

	for (i = 0; dnsentries[i] != NULL; i++) {
		if (strcmp(dnsentries[i], a) == 0) {
			/* found a match, now use the rbl name to get the result */
			if (strstr(a, "timeout") != NULL)
				return 2;
			return 0;
		}
	}

	return 1;
}

int
dnstxt(char **a, const char *b)
{
	if (b == NULL)
		return -1;

	*a = NULL;
	return 0;
}

#include "tls.h"
SSL *ssl;
