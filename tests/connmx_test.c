#include <qremote/conn.h>

#include <netio.h>
#include <qdns_dane.h>
#include <qremote/greeting.h>
#include "test_io/testcase_io.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *rhost;
static int wpipe = -1;
unsigned int smtpext;
static int greet_result, next_greet_result;
static int quitnext;
static int tls_result = -1;
unsigned int targetport = 428;
char *clientcertbuf;

void
quitmsg(void)
{
	printf("QUIT\n");

	close(socketd);
	socketd = -1;
	close(wpipe);
	wpipe = -1;
	if (!quitnext) {
		fprintf(stderr, "unexpected call to %s\n", __func__);
		abort();
	}
	quitnext = 0;
}

int
greeting(void)
{
	int ret = greet_result;

	greet_result = next_greet_result;
	next_greet_result = -1;

	return ret;
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
tls_init(void)
{
	int ret = tls_result;
	if (tls_result < 0)
		abort();

	tls_result = -1;

	return ret;
}

int
netget(const unsigned int terminate __attribute__ ((unused)))
{
	static unsigned int state;
	int msg;

	greet_result = 0;

	if (quitnext)
		abort();

	/* sequence */
	switch (state++) {
	case 0:
		msg = 550;
		quitnext = 1;
		break;
	case 1:
		msg = -220;
		break;
	case 2:
		greet_result = -1;
		msg = 220;
		quitnext = 1;
		break;
	case 3:
		msg = -440;
		break;
	case 4:
		msg = 440;
		quitnext = 1;
		break;
	case 5:
		msg = -220;
		break;
	case 6:
		msg = -440;
		break;
	case 7:
		greet_result = -1;
		msg = 220;
		quitnext = 1;
		break;
	case 8:
		msg = -220;
		break;
	case 9:
		snprintf(linein.s, TESTIO_MAX_LINELEN, "2xxxxx");
		printf("linein: %s\n", linein.s);
		quitnext = 1;
		return -EINVAL;
	case 10:
		msg = -220;
		break;
	case 11:
		greet_result = esmtp_8bitmime | esmtp_starttls;
		msg = 220;
		tls_result = 0;
		next_greet_result = -1;
		quitnext = 1;
		break;
	case 12:
		quitnext = 1;
		return -EINVAL;
	case 13:
		msg = -220;
		break;
	case 14:
		greet_result = esmtp_8bitmime | esmtp_starttls;
		msg = 220;
		tls_result = 1;
		quitnext = 1;
		break;
	case 15:
		greet_result = esmtp_8bitmime | esmtp_starttls;
		msg = 220;
		tls_result = 1;
		quitnext = 1;
		break;
	case 16:
		msg = -220;
		break;
	case 17:
		close(socketd);
		socketd = -1;
		printf("simulating ECONNRESET\n");
		return -ECONNRESET;
	case 18:
		msg = -220;
		break;
	case 19:
		greet_result = esmtp_8bitmime | esmtp_starttls;
		msg = 220;
		tls_result = 0;
		next_greet_result = esmtp_8bitmime;
		break;
	case 20:
		greet_result = esmtp_8bitmime;
		msg = 220;
		tls_result = 0;
		quitnext = 1;
		break;
	case 21:
		greet_result = esmtp_8bitmime;
		msg = 220;
		tls_result = 0;
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
tryconn(struct ips *mx, const struct in6_addr *outip4 __attribute__ ((unused)),
		const struct in6_addr *outip6 __attribute__ ((unused)))
{
	int p[2];
	static char namebuf[64];

	mx->name = namebuf;
	snprintf(namebuf, sizeof(namebuf), "prio%u.example.org", mx->priority);

	if (mx->priority == 0)
		return -ENOENT;

	mx->priority--;

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
dnstlsa(const char *host, const unsigned short port, struct daneinfo **out)
{
	assert(host != NULL);
	assert(out == NULL);
	assert(port == targetport);

	if (strcmp(host, "prio2.example.org") == 0)
		return 1;

	return 0;
}

int
main(void)
{
	struct ips mx[3];
	int ret = 0;
	int i;

	// run the first 9 subtests (one more because of the data_pending() failure in between */
	memset(mx, 0, sizeof(mx));
	mx[0].priority = 10;
	mx[0].next = mx + 1;
	mx[1].next = mx + 2;

	testcase_ignore_log_writen();

	i = connect_mx(mx, NULL, NULL);
	if (i != -ENOENT) {
		fprintf(stderr, "connect_mx() returned %i instead of %i (-ENOENT)\n", i, -ENOENT);
		ret++;
	}

	if (socketd >= 0)
		close(socketd);

	mx[0].priority = 1;

	i = connect_mx(mx, NULL, NULL);
	if (i != 0) {
		fprintf(stderr, "connect_mx() returned %i instead of 0\n", i);
		ret++;
	}

	if (socketd >= 0)
		close(socketd);

	mx[0].priority = 1;
	clientcertbuf = "";

	i = connect_mx(mx, NULL, NULL);
	if (i != -ENOENT) {
		fprintf(stderr, "connect_mx() returned %i instead of -ENOENT when expected STARTTLS was not offered\n", i);
		ret++;
	}

	if (socketd >= 0)
		close(socketd);

	mx[0].priority = 1;
	clientcertbuf = NULL;

	i = connect_mx(mx, NULL, NULL);
	if (i != 0) {
		fprintf(stderr, "connect_mx() returned %i instead of 0\n", i);
		ret++;
	}

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
	if (quitnext) {
		fprintf(stderr, "expected call to quitmsg() missing\n");
		ret++;
	}
	if (mx[0].priority != 0) {
		fprintf(stderr, "mx[0].priority is %u instead of 0\n", mx[0].priority);
		ret++;
	}

	return ret;
}
