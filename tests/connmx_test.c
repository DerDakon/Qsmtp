#include <qremote/conn.h>

#include <netio.h>
#include <qdns_dane.h>
#include <qremote/greeting.h>
#include "test_io/testcase_io.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

char *rhost;
static int wpipe = -1;
unsigned int smtpext;
static int greet_result, next_greet_result;
static int quitnext;
static int tls_result = -1;
unsigned int targetport = 428;
bool expect_tls;
static char rhostbuf[96];

#define MX_PRIORITY_SINGLE_TLSA 800

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

static struct ips testmx[3];

static void
mxsetup(struct ips *mx, const unsigned int priority)
{
	static char namebuf[64];

	mx->priority = priority;

	mx->name = namebuf;
	snprintf(namebuf, sizeof(namebuf), "prio%u.example.org", mx->priority);
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
		mxsetup(testmx, testmx[0].priority);
		msg = -220;
		break;
	case 2:
		greet_result = -1;
		msg = 220;
		quitnext = 1;
		break;
	case 3:
		mxsetup(testmx, testmx[0].priority);
		msg = -440;
		break;
	case 4:
		msg = 440;
		quitnext = 1;
		break;
	case 5:
		mxsetup(testmx, testmx[0].priority);
		msg = -220;
		break;
	case 6:
		msg = -440;
		break;
	case 7:
		greet_result = -1;
		msg = 220;
		quitnext = 1;
		log_write_msg = "invalid greeting from prio8.example.org [2001:db8::8]";
		log_write_priority = LOG_WARNING;
		break;
	case 8:
		mxsetup(testmx, testmx[0].priority);
		msg = -220;
		break;
	case 9:
		snprintf(linein.s, TESTIO_MAX_LINELEN, "2xxxxx");
		printf("linein: %s\n", linein.s);
		quitnext = 1;
		log_write_msg = "invalid greeting from prio7.example.org [2001:db8::7]";
		log_write_priority = LOG_WARNING;
		return -EINVAL;
	case 10:
		mxsetup(testmx, testmx[0].priority);
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
		log_write_msg = "invalid greeting from prio5.example.org [2001:db8::5]";
		log_write_priority = LOG_WARNING;
		return -EINVAL;
	case 13:
		mxsetup(testmx, testmx[0].priority);
		msg = -220;
		break;
	case 14:
		greet_result = esmtp_8bitmime | esmtp_starttls;
		msg = 220;
		tls_result = 1;
		quitnext = 1;
		break;
	case 15:
		mxsetup(testmx, testmx[0].priority);
		greet_result = esmtp_8bitmime | esmtp_starttls;
		msg = 220;
		tls_result = 1;
		quitnext = 1;
		break;
	case 16:
		mxsetup(testmx, testmx[0].priority);
		msg = -220;
		break;
	case 17:
		printf("simulating ECONNRESET after initial message\n");
		log_write_msg = "connection to prio2.example.org [2001:db8::2] died";
		log_write_priority = LOG_WARNING;
		return -ECONNRESET;
	case 18:
		printf("simulating ECONNRESET at initial message\n");
		log_write_msg = "connection to prio1.example.org [2001:db8::1] died";
		log_write_priority = LOG_WARNING;
		return -ECONNRESET;
	case 19:
		mxsetup(testmx, testmx[0].priority);
		msg = -220;
		break;
	case 20:
		greet_result = esmtp_8bitmime | esmtp_starttls;
		msg = 220;
		tls_result = 0;
		next_greet_result = esmtp_8bitmime;
		break;
	case 21:
	case 22:
		greet_result = esmtp_8bitmime;
		msg = 220;
		tls_result = 0;
		quitnext = 1;
		break;
	case 23:
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
	if ((mx->priority == 0) || (mx->priority == MX_PRIORITY_SINGLE_TLSA - 1))
		return -ENOENT;

	if (wpipe >= 0) {
		close(wpipe);
		wpipe = -1;
	}

	int p[2];
	if (pipe(p) != 0)
		exit(errno);

	wpipe = p[0];
	snprintf(rhostbuf, sizeof(rhostbuf), "%s [2001:db8::%u]", mx->name, mx->priority);
	rhost = rhostbuf;
	mx->priority--;

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
	assert(out != NULL);
	assert(port == targetport);

	if ((strcmp(host, "prio2.example.org") == 0) || (strcmp(host, "prio800.example.org") == 0)) {
		*out = malloc(sizeof(**out));
		memset(*out, 0, sizeof(**out));
		return 1;
	}

	return 0;
}

void
daneinfo_free(struct daneinfo *di, int cnt)
{
	for (int i = 0; i < cnt; i++)
		free(di[i].data);
	free(di);
}

int
main(void)
{
	int ret = 0;

	// run the first 9 subtests, two more because of the CONNRESETs in between */
	memset(testmx, 0, sizeof(testmx));
	testmx[0].next = testmx + 1;
	testmx[1].next = testmx + 2;
	mxsetup(testmx, 11);

	testcase_setup_log_writen(testcase_log_writen_combine);
	testcase_setup_log_write(testcase_log_write_compare);

	int i = connect_mx(testmx, NULL, NULL);
	if (i != -ENOENT) {
		fprintf(stderr, "connect_mx() returned %i instead of %i (-ENOENT)\n", i, -ENOENT);
		ret++;
	}

	if (socketd >= 0)
		close(socketd);

	mxsetup(testmx, 1);

	i = connect_mx(testmx, NULL, NULL);
	if (i != 0) {
		fprintf(stderr, "connect_mx() returned %i instead of 0\n", i);
		ret++;
	}

	if (socketd >= 0)
		close(socketd);

	mxsetup(testmx, 1);
	expect_tls = true;
	log_write_msg = "no STARTTLS offered by prio1.example.org [2001:db8::1], but TLS certificate is configured";
	log_write_priority = LOG_WARNING;

	i = connect_mx(testmx, NULL, NULL);
	if (i != -ENOENT) {
		fprintf(stderr, "connect_mx() returned %i instead of -ENOENT when expected STARTTLS was not offered because clientcert is configured\n", i);
		ret++;
	}

	if (socketd >= 0)
		close(socketd);

	mxsetup(testmx, MX_PRIORITY_SINGLE_TLSA);
	expect_tls = false;
	log_write_msg = "no STARTTLS offered by prio800.example.org [2001:db8::800], but TLSA record exists";
	log_write_priority = LOG_WARNING;

	i = connect_mx(testmx, NULL, NULL);
	if (i != -ENOENT) {
		fprintf(stderr, "connect_mx() returned %i instead of -ENOENT when expected STARTTLS was not offered because TLSA record is present\n", i);
		ret++;
	}

	if (socketd >= 0)
		close(socketd);

	mxsetup(testmx, 1);

	i = connect_mx(testmx, NULL, NULL);
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
	if (testmx[0].priority != 0) {
		fprintf(stderr, "mx[0].priority is %u instead of 0\n", testmx[0].priority);
		ret++;
	}

	return ret;
}
