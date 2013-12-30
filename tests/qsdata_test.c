#include "../qsmtpd/data.c"

#include <qsmtpd/antispam.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int relayclient;
unsigned long sslauth;
unsigned long databytes;
unsigned int goodrcpt;
int badbounce;
struct xmitstat xmitstat;
char *protocol;
const char *auth_host;
const char *auth_check;
const char **auth_sub;
const char **globalconf;
string heloname;
string msgidhost;
string liphost;
int socketd = 1;
long comstate = 0x001;
int authhide;
int submission_mode;

struct recip *thisrecip;

struct smtpcomm commands[8];

// override this so always the same time is returned for testcases
static time_t testtime;

time_t
time(time_t *t __attribute__ ((unused)))
{
	return testtime;
}

pid_t
fork_clean()
{
	return -1;
}

void
freedata(void)
{
}

void
tarpit(void)
{
}

void
sync_pipelining(void)
{
}

int
spfreceived(int fd, const int spf)
{
	char buf[64];
	ssize_t r;

	snprintf(buf, sizeof(buf), "Received-SPF: testcase, spf %i\n", spf);

	r = write(fd, buf, strlen(buf));

	if ((r == (ssize_t)strlen(buf)) && (r > 0))
		return 0;
	else
		return -1;
}

static int
check_twodigit(void)
{
	int ret = 0;
	int i;

	for (i = 0; i < 100; i++) {
		char mine[3];
		char other[3];

		snprintf(other, sizeof(other), "%02i", i);
		two_digit(mine, i);
		mine[2] = '\0';

		if (strcmp(mine, other)) {
			ret++;

			fprintf(stderr, "two_digit(%i) = %s\n", i, mine);
		}
	}

	return ret;
}

static const time_t time2012 = 1334161937;
static const char * timestr2012 = "Wed, 11 Apr 2012 18:32:17 +0200";

static int
check_date822(void)
{
	char buf[32];
	const char *expt[] = { "Thu, 01 Jan 1970 00:00:00 +0000", timestr2012 };
	const time_t testtimes[] = { 0, time2012 };
	const char *tzones[] = { "TZ=UTC", "TZ=CET" };
	int ret = 0;
	int i;
	char tzbuf[12];

	memset(buf, 0, sizeof(buf));

	for (i = 0; i < 2; i++) {
		testtime = testtimes[i];
		memcpy(tzbuf, tzones[i], strlen(tzones[i]) + 1);
		putenv(tzbuf);
		date822(buf);

		if (strcmp(buf, expt[i])) {
			ret++;
			fprintf(stderr, "time %li was encoded to '%s' instead of '%s'\n",
					(long) testtimes[i], buf, expt[i]);
		}
	}

	return ret;
}

static int
check_queueheader(void)
{
	struct recip to;
	int err = 0;
	int idx;

	if (pipe(fd0) != 0)
		return 1;

	if (fcntl(fd0[0] ,F_SETFL,fcntl(fd0[0] ,F_GETFL) | O_NONBLOCK) != 0)
		return 2;

	/* setup */
	testtime = time2012;
	protocol = "TEST_PROTOCOL";
	to.ok = 1;
	to.to.s = "test@example.com";
	to.to.len = strlen(to.to.s);

	heloname.s = "testcase.example.net";
	heloname.len = strlen(heloname.s);

	thisrecip = &to;

	TAILQ_INIT(&head);
	TAILQ_INSERT_TAIL(&head, &to, entries);

	for (idx = 0; idx < 13; idx++) {
		char outbuf[2048];
		ssize_t off = 0;
		ssize_t mismatch = -1;
		const char *expect;
		const char *testname;

		memset(&xmitstat, 0, sizeof(xmitstat));

		strncpy(xmitstat.remoteip, "192.0.2.42", sizeof(xmitstat.remoteip));

		switch (idx) {
		case 0:
			testname = "minimal";
			relayclient = 1;
			expect = "Received: from unknown ([192.0.2.42])\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with TEST_PROTOCOL\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 1:
			testname = "reverse DNS";
			relayclient = 1;
			xmitstat.remotehost.s = "sender.example.net";
			expect = "Received: from sender.example.net ([192.0.2.42])\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with TEST_PROTOCOL\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 2:
			testname = "reverse DNS and port";
			relayclient = 1;
			xmitstat.remotehost.s = "sender.example.net";
			xmitstat.remoteport = "42";
			expect = "Received: from sender.example.net ([192.0.2.42]:42)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with TEST_PROTOCOL\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 3:
			testname = "minimal + HELO";
			relayclient = 1;
			xmitstat.helostr.s = "sender";
			expect = "Received: from unknown ([192.0.2.42] HELO sender)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with TEST_PROTOCOL\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 4:
			testname = "minimal + SPF";
			relayclient = 0;
			xmitstat.spf = SPF_PASS;
			expect = "Received-SPF: testcase, spf 1\n"
					"Received: from unknown ([192.0.2.42])\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with TEST_PROTOCOL\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 5:
			testname = "minimal + auth";
			relayclient = 1;
			xmitstat.authname.s = "authuser";
			expect = "Received: from unknown ([192.0.2.42]) (auth=authuser)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with TEST_PROTOCOLA\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 6:
			testname = "authhide";
			/* no relayclient, but since we are authenticated there must not be a SPF header */
			relayclient = 0;
			authhide = 1;
			xmitstat.authname.s = "authuser";
			expect = "Received: (auth=authuser)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with TEST_PROTOCOLA\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 7:
			testname = "authhide + cert";
			/* no relayclient, but since we are authenticated there must not be a SPF header */
			relayclient = 0;
			authhide = 1;
			xmitstat.tlsclient = "mail@cert.example.com";
			expect = "Received: (cert=mail@cert.example.com)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with TEST_PROTOCOL\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 8:
			/* no relayclient, not authenticated, authhide should be ignored */
			testname = "authhide + ident";
			relayclient = 0;
			authhide = 1;
			xmitstat.remoteinfo = "auth=foo"; /* fake attempt */
			xmitstat.spf = SPF_PASS;
			expect = "Received-SPF: testcase, spf 1\n"
					"Received: from unknown ([192.0.2.42]) (ident=auth=foo)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with TEST_PROTOCOL\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 9:
			testname = "minimal + ident";
			relayclient = 1;
			authhide = 0;
			xmitstat.remoteinfo = "auth=foo"; /* fake attempt */
			expect = "Received: from unknown ([192.0.2.42]) (ident=auth=foo)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with TEST_PROTOCOL\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 10:
			testname = "minimal + cert + ident";
			xmitstat.remoteinfo = "something"; /* should have no effect as tlsclient is set */
			/* fallthrough */
		case 11:
			if (idx == 1) {
				testname = "minimal + cert";
			}
			relayclient = 0;
			authhide = 0;
			xmitstat.tlsclient = "mail@cert.example.com";
			expect = "Received: from unknown ([192.0.2.42]) (cert=mail@cert.example.com)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with TEST_PROTOCOL\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 12:
			testname = "chunked";
			chunked = 1;
			authhide = 0;
			relayclient = 1;
			expect = "Received: from unknown ([192.0.2.42])\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with (chunked) TEST_PROTOCOL\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
		}

		if (xmitstat.remotehost.s != NULL)
			xmitstat.remotehost.len = strlen(xmitstat.remotehost.s);
		if (xmitstat.helostr.s != NULL)
			xmitstat.helostr.len = strlen(xmitstat.helostr.s);
		if (xmitstat.authname.s != NULL)
			xmitstat.authname.len = strlen(xmitstat.authname.s);

		printf("Running test: %s\n", testname);

		if (queue_header()) {
			err = 3;
			break;
		}

		while (off < (ssize_t)sizeof(outbuf) - 1) {
			ssize_t r = read(fd0[0], outbuf + off, 1);
			if (r < 0) {
				if (errno != EAGAIN) {
					fprintf(stderr, "read failed with error %i\n", errno);
					err = 4;
				}
				break;
			}
			if ((mismatch < 0) && (outbuf[off] != expect[off])) {
				mismatch = off;
				fprintf(stderr, "output mismatch at position %zi, got %c (0x%02x), expected %c (0x%02x)\n",
					mismatch, outbuf[off], outbuf[off], expect[off], expect[off]);
				err = 5;
				// do not break, read the whole input
			}
			off++;
		}
		outbuf[off] = '\0';

		if (err != 0) {
			fprintf(stderr, "expected output not found, got:\n%s\nexpected:\n%s\n", outbuf, expect);
			if (strlen(outbuf) != strlen(expect))
				fprintf(stderr, "expected length: %zi, got length: %zi\n", strlen(expect), strlen(outbuf));
			break;
		}

		if (off == sizeof(outbuf) - 1) {
			fprintf(stderr, "too long output received\n");
			err = 6;
			break;
		} else if (off == 0) {
			fprintf(stderr, "no output received\n");
			err = 7;
			break;
		}
	}

	close(fd0[0]);
	close(fd0[1]);

	/* pass invalid fds in, this should cause the write() to fail */
	fd0[0] = -1;
	fd0[1] = -1;

	relayclient = 0;
	xmitstat.spf = SPF_PASS;

	if (queue_header() != -1) {
		fprintf(stderr, "queue_header() for fd -1 did not fail\n");
		err = 8;
	} else if (errno != EBADFD) {
		fprintf(stderr, "queue_header() for fd -1 did not set errno to EBADFD, but to %i\n",
				errno);
		err = 9;
	}

	return err;
}

int main()
{
	int ret = 0;

	memset(&xmitstat, 0, sizeof(xmitstat));

	ret += check_twodigit();
	ret += check_date822();
	ret += check_queueheader();

	return ret;
}
