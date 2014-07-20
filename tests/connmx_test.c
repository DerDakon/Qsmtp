#include <qremote/conn.h>

#include <netio.h>
#include <qremote/greeting.h>
#include "test_io/testcase_io.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *rhost;
static int wpipe = -1;
unsigned int smtpext;
static int greet_result;
static unsigned int quitcnt = 5;

void
quitmsg(void)
{
	printf("QUIT\n");

	close(socketd);
	socketd = -1;
	close(wpipe);
	wpipe = -1;
	if (quitcnt-- == 0) {
		fprintf(stderr, "unexpected call to %s\n", __func__);
		abort();
	}
}

int
greeting(void)
{
	return greet_result;
}

void
err_mem(const int doquit __attribute__ ((unused)))
{
	exit(ENOMEM);
}

void
write_status(const char *str __attribute__ ((unused)))
{
}

void
write_status_m(const char **strs __attribute__ ((unused)), const unsigned int count __attribute__ ((unused)))
{
}

int
netget(const unsigned int terminate __attribute__ ((unused)))
{
	static unsigned int state;
	int msg;

	greet_result = 0;

	/* sequence */
	switch (state++) {
	case 0:
		msg = 550;
		break;
	case 1:
	case 5:
	case 8:
	case 10:
		msg = -220;
		break;
	case 2:
	case 7:
		greet_result = -1;
		msg = 220;
		break;
	case 3:
	case 6:
		msg = -440;
		break;
	case 4:
		msg = 440;
		break;
	case 9:
		snprintf(linein.s, TESTIO_MAX_LINELEN, "2xxxxx");
		printf("linein: %s\n", linein.s);
		return -EINVAL;
	case 11:
		greet_result = esmtp_8bitmime;
		msg = 220;
		break;
	default:
		abort();
	}

	if (msg < 0) {
		snprintf(linein.s, TESTIO_MAX_LINELEN, "%3u-", -msg);
		msg *= -1;
	} else {
		snprintf(linein.s, TESTIO_MAX_LINELEN, "%3u ", msg);
	}

	printf("linein: %s\n", linein.s);

	return msg;
}

int
tryconn(struct ips *mx __attribute__ ((unused)), const struct in6_addr *outip4 __attribute__ ((unused)),
		const struct in6_addr *outip6 __attribute__ ((unused)))
{
	int p[2];

	if (pipe(p) != 0)
		exit(errno);

	wpipe = p[0];

	return p[1];
}

void
getrhost(const struct ips *mx __attribute__ ((unused)))
{
}

int
main(void)
{
	struct ips mx[3];
	int ret = 0;

	memset(mx, 0, sizeof(mx));
	mx[0].next = mx + 1;
	mx[1].next = mx + 2;

	testcase_ignore_log_writen();

	connect_mx(mx, NULL, NULL);

	if (close(socketd) != 0)
		ret++;
	if (close(0) != 0)
		ret++;
	if (close(wpipe) != 0)
		ret++;
	if (smtpext != esmtp_8bitmime) {
		fprintf(stderr, "smtpext was %x instead of %x\n", smtpext, esmtp_8bitmime);
		ret++;
	}
	if (quitcnt != 0) {
		fprintf(stderr, "quitcnt was %i instead of 0\n", quitcnt);
		ret++;
	}

	return ret;
}
