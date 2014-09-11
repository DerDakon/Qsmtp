#include "../qsmtpd/data.c"

#include <qsmtpd/antispam.h>
#include "test_io/testcase_io.h"
#include <version.h>

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
const char **globalconf;
string heloname;
string msgidhost;
string liphost;
unsigned int comstate = 0x001;
int authhide;
int submission_mode;
int queuefd_data = -1;
int queuefd_hdr = -1;

struct recip *thisrecip;

static struct smtpcomm commands; /* only this one is ever used */
struct smtpcomm *current_command = &commands;

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

void
queue_reset(void)
{
	exit(EFAULT);
}

static int queue_init_result = -1;

int
queue_init(void)
{
	int r = queue_init_result;

	switch (queue_init_result) {
	case 0:
	case EDONE:
		queue_init_result = -1;
		return r;
	default:
		exit(EFAULT);
	}
}

int
queue_envelope(const unsigned long sz __attribute__ ((unused)), const int chunked __attribute__ ((unused)))
{
	exit(EFAULT);
}

int
queue_result(void)
{
	exit(EFAULT);
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
	int fd0[2];

	if (pipe(fd0) != 0)
		return 1;

	if (fcntl(fd0[0], F_SETFL, fcntl(fd0[0], F_GETFL) | O_NONBLOCK) != 0)
		return 2;

	/* setup */
	testtime = time2012;
	to.ok = 1;
	to.to.s = "test@example.com";
	to.to.len = strlen(to.to.s);

	heloname.s = "testcase.example.net";
	heloname.len = strlen(heloname.s);

	thisrecip = &to;

	TAILQ_INIT(&head);
	TAILQ_INSERT_TAIL(&head, &to, entries);

	queuefd_data = fd0[1];

	for (idx = 0; idx < 14; idx++) {
		char outbuf[2048];
		ssize_t off = 0;
		ssize_t mismatch = -1;
		const char *expect;
		const char *testname;
		int chunked = 0;
		static const char received_from[] = "Received: from ";

		memset(&xmitstat, 0, sizeof(xmitstat));

		strncpy(xmitstat.remoteip, "192.0.2.42", sizeof(xmitstat.remoteip));

		switch (idx) {
		case 0:
			testname = "minimal";
			relayclient = 1;
			expect = "Received: from unknown ([192.0.2.42])\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with SMTP\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 1:
			testname = "reverse DNS";
			relayclient = 1;
			xmitstat.remotehost.s = "sender.example.net";
			expect = "Received: from sender.example.net ([192.0.2.42])\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with SMTP\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 2:
			testname = "reverse DNS and port";
			relayclient = 1;
			xmitstat.remotehost.s = "sender.example.net";
			xmitstat.remoteport = "42";
			expect = "Received: from sender.example.net ([192.0.2.42]:42)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with SMTP\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 3:
			testname = "minimal + HELO";
			relayclient = 1;
			xmitstat.helostr.s = "sender";
			expect = "Received: from unknown ([192.0.2.42] HELO sender)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with SMTP\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 4:
			testname = "minimal + SPF";
			relayclient = 0;
			xmitstat.spf = SPF_PASS;
			expect = "Received-SPF: testcase, spf 1\n"
					"Received: from unknown ([192.0.2.42])\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with SMTP\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 5:
			testname = "minimal + auth";
			relayclient = 1;
			xmitstat.authname.s = "authuser";
			expect = "Received: from unknown ([192.0.2.42]) (auth=authuser)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with ESMTPA\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 6:
			testname = "authhide";
			/* no relayclient, but since we are authenticated there must not be a SPF header */
			relayclient = 0;
			authhide = 1;
			xmitstat.authname.s = "authuser";
			expect = "Received: from unknown (auth=authuser)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with ESMTPA\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 7:
			testname = "authhide + cert";
			/* no relayclient, but since we are authenticated there must not be a SPF header */
			relayclient = 0;
			authhide = 1;
			xmitstat.tlsclient = "mail@cert.example.com";
			expect = "Received: from unknown (cert=mail@cert.example.com)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with SMTP\n"
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
					"\tby testcase.example.net (" VERSIONSTRING ") with SMTP\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 9:
			testname = "minimal + ident";
			relayclient = 1;
			authhide = 0;
			xmitstat.remoteinfo = "auth=foo"; /* fake attempt */
			expect = "Received: from unknown ([192.0.2.42]) (ident=auth=foo)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with SMTP\n"
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
					"\tby testcase.example.net (" VERSIONSTRING ") with SMTP\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 12:
			testname = "chunked";
			chunked = 1;
			authhide = 0;
			relayclient = 1;
			expect = "Received: from unknown ([192.0.2.42])\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with (chunked) ESMTP\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 13:
			/* no relayclient, authenticated, authhide, ident should be ignored */
			testname = "auth + authhide + ident";
			relayclient = 0;
			authhide = 1;
			chunked = 0;
			xmitstat.remoteinfo = "auth=foo"; /* fake attempt */
			xmitstat.authname.s = "authuser";
			expect = "Received: from unknown (auth=authuser)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with ESMTPA\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		}

		if (xmitstat.remotehost.s != NULL)
			xmitstat.remotehost.len = strlen(xmitstat.remotehost.s);
		if (xmitstat.helostr.s != NULL)
			xmitstat.helostr.len = strlen(xmitstat.helostr.s);
		if (xmitstat.authname.s != NULL)
			xmitstat.authname.len = strlen(xmitstat.authname.s);

		if ((xmitstat.authname.s != NULL) || chunked)
			xmitstat.esmtp = 1;

		printf("%s: Running test: %s\n", __func__, testname);

		if (write_received(chunked)) {
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

		/* to make sure a syntactically valid line is always received */
		if (strstr(outbuf, received_from) == NULL) {
			fprintf(stderr, "'Received: from ' not found in output\n");
			err = 10;
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

	/* pass invalid fd in, this should cause the write() to fail */
	queuefd_data = -1;

	relayclient = 0;
	xmitstat.spf = SPF_PASS;

	if (write_received(0) != -1) {
		fprintf(stderr, "queue_header() for fd -1 did not fail\n");
		err = 8;
	} else if (errno != EBADF) {
		fprintf(stderr, "queue_header() for fd -1 did not set errno to EBADF, but to %i\n",
				errno);
		err = 9;
	}

	return err;
}

static int
check_check_rfc822_headers(void)
{
	const char tohdr[] = "To: <foo@example.com>";
	const char fromhdr[] = "From: <foo@example.com>";
	const char datehdr[] = "Date: Sun, 15 Jun 2014 18:26:30 +0200";
	const char msgidhdr[] = "message-id: <12345@example.com>"; /* intentionally lowercase */
	struct tc {
		const char *hdrname;		/* expected hdrname */
		const unsigned int flagsb;	/* flags before test */
		const unsigned int flagsa;	/* flags after test */
		const int rc;			/* expected return code */
		const char *pattern;		/* input line */
	} testdata[] = {
		{
			.pattern = ""
		},
		{
			.pattern = tohdr
		},
		{
			.pattern = datehdr,
			.flagsa = 1,
			.rc = 1
		},
		{
			.pattern = fromhdr,
			.flagsa = 2,
			.rc = 1
		},
		{
			.pattern = msgidhdr,
			.flagsa = 4,
			.rc = 1
		},
		{
			.pattern = datehdr,
			.flagsb = 2,
			.flagsa = 3,
			.rc = 1
		},
		{
			.pattern = fromhdr,
			.flagsb = 1,
			.flagsa = 3,
			.rc = 1
		},
		{
			.pattern = msgidhdr,
			.flagsb = 2,
			.flagsa = 6,
			.rc = 1
		},
		{
			.hdrname = "Date:",
			.pattern = datehdr,
			.flagsb = 1,
			.flagsa = 1,
			.rc = -2
		},
		{
			.hdrname = "From:",
			.pattern = fromhdr,
			.flagsb = 2,
			.flagsa = 2,
			.rc = -2
		},
		{
			.hdrname = "Message-Id:",
			.pattern = msgidhdr,
			.flagsb = 4,
			.flagsa = 4,
			.rc = -2
		},
		{
			.rc = -8,
			.pattern = "X-\222"
		},
		{
			.rc = 0,
			.pattern = "D"
		},
		{
			.pattern = NULL
		},
	};
	int ret = 0;
	unsigned int i;

	for (i = 0; testdata[i].pattern != NULL; i++) {
		const char *hdrname = NULL;
		unsigned int hdrflags = testdata[i].flagsb;

		printf("%s: Running test: '%s'\n", __func__, testdata[i].pattern);
		linein.len = strlen(testdata[i].pattern);
		memcpy(linein.s, testdata[i].pattern, linein.len);
		linein.s[linein.len] = '\0';

		int r = check_rfc822_headers(&hdrflags, &hdrname);

		if (r != testdata[i].rc) {
			fprintf(stderr, "%s[%u]: return code mismatch, got %i, expected %i\n",
					__func__, i, r, testdata[i].rc);
			ret++;
		} else if ((hdrname != NULL) && (testdata[i].hdrname != NULL)) {
			if (strcmp(hdrname, testdata[i].hdrname) != 0) {
				fprintf(stderr, "%s[%u]: header name mismatch, got '%s', expected '%s'\n",
					__func__, i, hdrname, testdata[i].hdrname);
				ret++;
			}
		} else if ((hdrname != NULL) ^ (testdata[i].hdrname != NULL)) {
			fprintf(stderr, "%s[%u]: header name mismatch, got '%s', expected '%s'\n",
				__func__, i, hdrname, testdata[i].hdrname);
			ret++;
		} else if (hdrflags != testdata[i].flagsa) {
			fprintf(stderr, "%s[%u]: flags mismatch, got %u, expected %u\n",
				__func__, i, hdrflags, testdata[i].flagsa);
			ret++;
		}
	}

	return ret;
}

static int
check_data_badbounce()
{
	int ret = 0;
	int r;

	printf("%s\n", __func__);
	netnwrite_msg = "554 5.1.1 no valid recipients\r\n";
	badbounce = 1;
	goodrcpt = 1;

	r = smtp_data();

	if (r != EDONE)
		ret++;

	ret += testcase_netnwrite_check(__func__);

	return ret;
}

static int
check_data_no_rcpt()
{
	int ret = 0;
	int r;

	printf("%s\n", __func__);
	netnwrite_msg = "554 5.1.1 no valid recipients\r\n";
	badbounce = 0;
	goodrcpt = 0;

	r = smtp_data();

	if (r != EDONE)
		ret++;

	ret += testcase_netnwrite_check(__func__);

	return ret;
}

static int
check_data_qinit_fail()
{
	int ret = 0;
	int r;

	printf("%s\n", __func__);
	badbounce = 0;
	goodrcpt = 1;
	queue_init_result = EDONE;

	r = smtp_data();

	if (r != EDONE)
		ret++;

	return ret;
}

int main()
{
	int ret = 0;

	memset(&xmitstat, 0, sizeof(xmitstat));

	testcase_setup_netnwrite(testcase_netnwrite_compare);

	socketd = 1;

	ret += check_twodigit();
	ret += check_date822();
	ret += check_queueheader();
	ret += check_check_rfc822_headers();
	ret += check_data_badbounce();
	ret += check_data_no_rcpt();
	ret += check_data_qinit_fail();

	return ret;
}
