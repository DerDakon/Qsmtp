#include "antispam.h"
#include "qsmtpd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct xmitstat xmitstat;

static int
test_reverseip()
{
	int err = 0;
	char buf[INET_ADDRSTRLEN];
	int r;

	memset(&xmitstat, 0, sizeof(xmitstat));
	memset(buf, 0, sizeof(buf));
	inet_pton(AF_INET6, "::ffff:1.2.3.4", &xmitstat.sremoteip);
	r = reverseip4(buf);

	if (strcmp(buf, "4.3.2.1") != 0) {
		fprintf(stderr, "reverseip4() returned bad string %s\n", buf);
		err++;
	}

	/* strlen("4.3.2.1") */
	if (r != 7) {
		fprintf(stderr, "reverseip4() returned bad length %i\n", r);
		err++;
	}

	return err;
}

int
main(void)
{
	int err = 0;

	err += test_reverseip();

	return err;
}


void log_writen(int priority __attribute__ ((unused)), const char **msg __attribute__ ((unused)))
{
}

inline void log_write(int priority __attribute__ ((unused)), const char *msg __attribute__ ((unused)))
{
}

int data_pending(void)
{
	return 1;
}

int
ask_dnsa(const char *a, struct ips **b)
{
	if (a == NULL) {
		errno = EINVAL;
		return -1;
	}
	*b = NULL;
	errno = ETIMEDOUT;
	return -1;
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
