#include "antispam.h"
#include "qsmtpd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct xmitstat xmitstat;

static unsigned int logcount;

static int
test_rbl()
{
	int err = 0;


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
