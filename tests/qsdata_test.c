#include "../qsmtpd/data.c"

#include <qsmtpd/antispam.h>
#include "test_io/testcase_io.h"
#include <version.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <sys/signal.h>
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
unsigned long comstate = 0x001;
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

int
gettimeofday(struct timeval *tv, struct timezone *tz)
{
	if ((tz != NULL) && ((tz->tz_dsttime != 0) || (tz->tz_minuteswest != 0)))
		abort();

	if (tv == NULL)
		abort();

	tv->tv_sec = time(NULL);
	tv->tv_usec = 10203042;

	return 0;
}

static SSL dummy_ssl;
static SSL_CIPHER dummy_cipher;
#define DUMMY_CIPHER_STRING "<OPENSSL_CIPHER_STRING_DUMMY>"

const SSL_CIPHER *
SSL_get_current_cipher(const SSL *s)
{
	if (s != &dummy_ssl)
		abort();

	return &dummy_cipher;
}

const char *
SSL_CIPHER_get_name(const SSL_CIPHER *c)
{
	if (c != &dummy_cipher)
		abort();

	return DUMMY_CIPHER_STRING;
}

pid_t
fork_clean()
{
	return -1;
}

void
freedata(void)
{
	while (!TAILQ_EMPTY(&head)) {
		struct recip *l = TAILQ_FIRST(&head);

		TAILQ_REMOVE(&head, TAILQ_FIRST(&head), entries);
		free(l->to.s);
		free(l);
	}
}

void
tarpit(void)
{
}

void
sync_pipelining(void)
{
}

static int queue_reset_expected;
static char tzbuf[12];

void
queue_reset(void)
{
	if (queue_reset_expected != 1)
		exit(EFAULT);
	queue_reset_expected = 0;
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

static unsigned long expect_queue_envelope = -1;
static unsigned int expect_queue_result;
static int expect_queue_chunked;

int
queue_envelope(const unsigned long sz, const int chunked)
{
	if (expect_queue_envelope == (unsigned long)-1)
		abort();

	if (sz != expect_queue_envelope)
		abort();

	if (chunked != expect_queue_chunked)
		abort();

	expect_queue_envelope = -1;
	expect_queue_result = 1;

	// clean up the envelope, the real function does this, too
	// if it would be kept here the testcase could cause strange crashes if a different
	// code path is accidentially run which would free that data elsewhere
	while (!TAILQ_EMPTY(&head)) {
		struct recip *l = TAILQ_FIRST(&head);

		TAILQ_REMOVE(&head, TAILQ_FIRST(&head), entries);
		free(l->to.s);
		free(l);
	}
	thisrecip = NULL;

	return 0;
}

int
queue_result(void)
{
	if (expect_queue_result != 1)
		abort();

	expect_queue_result = 0;

	return 0;
}

int
spfreceived(int fd, const int spf)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "Received-SPF: testcase, spf %i\n", spf);

	const ssize_t r = write(fd, buf, strlen(buf));

	if ((r == (ssize_t)strlen(buf)) && (r > 0))
		return 0;
	else
		return -1;
}

static unsigned int pass_354;

int
test_netnwrite(const char *msg, const size_t len)
{
	const char msg354[] = "354 Start mail input; end with <CRLF>.<CRLF>\r\n";

	if (pass_354 || (netnwrite_msg == NULL)) {
		if (len != strlen(msg354))
			abort();

		if (strcmp(msg, msg354) != 0)
			abort();

		if (pass_354) {
			pass_354 = 0;
			return 0;
		}

		errno = 4321;
		return -1;
	} else {
		return testcase_netnwrite_compare(msg, len);
	}
}

static int
check_twodigit(void)
{
	int ret = 0;

	for (int i = 0; i < 100; i++) {
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
	char buf[32] = { 0 };
	const char *expt[] = { "Thu, 01 Jan 1970 00:00:00 +0000", timestr2012 };
	const time_t testtimes[] = { 0, time2012 };
	const char *tzones[] = { "TZ=UTC", "TZ=CET" };
	int ret = 0;

	for (int i = 0; i < 2; i++) {
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
setup_recip(void)
{
	thisrecip = malloc(sizeof(*thisrecip));
	if (thisrecip == NULL)
		return 3;

	thisrecip->ok = 1;
	thisrecip->to.s = strdup("test@example.com");
	if (thisrecip->to.s == NULL) {
		free(thisrecip);
		thisrecip = NULL;
		return 3;
	}
	thisrecip->to.len = strlen(thisrecip->to.s);

	TAILQ_INIT(&head);
	TAILQ_INSERT_TAIL(&head, thisrecip, entries);

	return 0;
}

static int
setup_datafd(int *fd0)
{
	if (pipe(fd0) != 0)
		return 1;

	if (fcntl(fd0[0], F_SETFL, fcntl(fd0[0], F_GETFL) | O_NONBLOCK) != 0) {
		close(fd0[0]);
		close(fd0[1]);
		return 2;
	}

	/* setup */
	testtime = time2012;

	heloname.s = "testcase.example.net";
	heloname.len = strlen(heloname.s);

	queuefd_data = fd0[1];

	int r = setup_recip();
	if (r != 0) {
		close(fd0[0]);
		close(fd0[1]);
		return r;
	}

	return 0;
}

static int
check_msgbody(const char *expect, int queuefd_read)
{
	int err = 0;
	ssize_t off = 0;
	ssize_t mismatch = -1;
	char outbuf[2048];
	static const char received_from[] = "Received: from ";

	while (off < (ssize_t)sizeof(outbuf) - 1) {
		const ssize_t r = read(queuefd_read, outbuf + off, 1);
		if (r < 0) {
			if (errno != EAGAIN) {
				fprintf(stderr, "read failed with error %i\n", errno);
				err = 5;
			}
			return err;
		}
		if (r == 0)
			break;
		if ((mismatch < 0) && (outbuf[off] != expect[off])) {
			mismatch = off;
			fprintf(stderr, "output mismatch at position %zi, got %c (0x%02x), expected %c (0x%02x)\n",
				mismatch, outbuf[off], outbuf[off], expect[off], expect[off]);
			err = 6;
			// do not break, read the whole input
		}
		off++;
	}
	outbuf[off] = '\0';

	if ((err != 0) || (off != strlen(expect))) {
		fprintf(stderr, "expected output not found, got:\n%s\nexpected:\n%s\n", outbuf, expect);
		if (strlen(outbuf) != strlen(expect))
			fprintf(stderr, "expected length: %zi, got length: %zi\n", strlen(expect), strlen(outbuf));
		return ++err;
	}

	/* to make sure a syntactically valid line is always received */
	if (strstr(outbuf, received_from) == NULL) {
		fprintf(stderr, "'Received: from ' not found in output\n");
		return 10;
	}

	if (off == sizeof(outbuf) - 1) {
		fprintf(stderr, "too long output received\n");
		return 7;
	} else if (off == 0) {
		fprintf(stderr, "no output received\n");
		return 8;
	}

	return 0;
}

static int
check_queueheader(void)
{
	int fd0[2];
	int err = setup_datafd(fd0);

	if (err != 0)
		return err;

	for (int idx = 0; idx < 16; idx++) {
		const char *expect;
		const char *testname;
		int chunked = 0;

		memset(&xmitstat, 0, sizeof(xmitstat));
		ssl = NULL;

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
			if (idx == 11)
				testname = "minimal + cert";
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
			xmitstat.remoteinfo = "auth=foo"; /* fake attempt */
			xmitstat.authname.s = "authuser";
			expect = "Received: from unknown (auth=authuser)\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with ESMTPA\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 14:
			/* plain SSL mail */
			testname = "SSL minimal";
			relayclient = 1;
			ssl = &dummy_ssl;
			expect = "Received: from unknown ([192.0.2.42])\n"
				"\tby testcase.example.net (" VERSIONSTRING ") with (" DUMMY_CIPHER_STRING " encrypted) ESMTPS\n"
				"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 15:
			/* plain SSL mail */
			testname = "SSL chunked";
			relayclient = 1;
			ssl = &dummy_ssl;
			chunked = 1;
			expect = "Received: from unknown ([192.0.2.42])\n"
			"\tby testcase.example.net (" VERSIONSTRING ") with (chunked " DUMMY_CIPHER_STRING " encrypted) ESMTPS\n"
			"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		}

		if (xmitstat.remotehost.s != NULL)
			xmitstat.remotehost.len = strlen(xmitstat.remotehost.s);
		if (xmitstat.helostr.s != NULL)
			xmitstat.helostr.len = strlen(xmitstat.helostr.s);
		if (xmitstat.authname.s != NULL)
			xmitstat.authname.len = strlen(xmitstat.authname.s);

		if ((xmitstat.authname.s != NULL) || chunked || ssl)
			xmitstat.esmtp = 1;

		printf("%s: Running test: %s\n", __func__, testname);

		if (write_received(chunked)) {
			err = 4;
			break;
		}

		err = check_msgbody(expect, fd0[0]);
		if (err != 0)
			break;
	}

	close(fd0[0]);
	close(fd0[1]);

	struct recip *l = TAILQ_FIRST(&head);

	TAILQ_REMOVE(&head, TAILQ_FIRST(&head), entries);
	free(l->to.s);
	free(l);
	thisrecip = NULL;
	if (!TAILQ_EMPTY(&head))
		abort();

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

	for (unsigned int i = 0; testdata[i].pattern != NULL; i++) {
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
check_data_badbounce(void)
{
	int ret = 0;

	printf("%s\n", __func__);
	netnwrite_msg = "554 5.1.1 no valid recipients\r\n";
	badbounce = 1;
	goodrcpt = 1;

	int r = smtp_data();

	if (r != EDONE)
		ret++;

	ret += testcase_netnwrite_check(__func__);

	return ret;
}

static int
check_data_no_rcpt(void)
{
	int ret = 0;

	printf("%s\n", __func__);
	netnwrite_msg = "554 5.1.1 no valid recipients\r\n";
	badbounce = 0;
	goodrcpt = 0;

	int r = smtp_data();

	if (r != EDONE)
		ret++;

	ret += testcase_netnwrite_check(__func__);

	return ret;
}

static int
check_data_qinit_fail(void)
{
	int ret = 0;

	printf("%s\n", __func__);
	badbounce = 0;
	goodrcpt = 1;
	queue_init_result = EDONE;

	int r = smtp_data();

	if (r != EDONE)
		ret++;

	return ret;
}

static int
check_data_354_fail(void)
{
	int ret = 0;

	printf("%s\n", __func__);

	badbounce = 0;
	goodrcpt = 1;
	queue_init_result = 0;
	queue_reset_expected = 1;

	int r = smtp_data();

	if (r != 4321)
		ret++;

	return ret;
}

static int
check_data_write_received_fail(void)
{
	int ret = 0;
	char logbuf[256];

	printf("%s\n", __func__);

	badbounce = 0;
	goodrcpt = 1;
	queue_init_result = 0;
	queue_reset_expected = 1;
	pass_354 = 1;
	net_read_msg = ".";
	net_read_fatal = 1;
	netnwrite_msg = "451 4.3.0 error writing mail to queue\r\n";
	snprintf(logbuf, sizeof(logbuf), "error in DATA: %s", strerror(EBADF));
	log_write_msg = logbuf;
	log_write_priority = LOG_ERR;

	queuefd_data = -1;
	queuefd_hdr = -1;

	setup_recip();

	int r = smtp_data();

	if (r != EDONE)
		ret++;

	return ret;
}

static int
check_data_write_received_pipefail(void)
{
	int ret = 0;
	int fd0[2];
	int r = setup_datafd(fd0);

	printf("%s\n", __func__);

	if (r != 0)
		return r;

	badbounce = 0;
	goodrcpt = 1;
	queue_init_result = 0;
	queue_reset_expected = 1;
	pass_354 = 1;
	net_read_msg = ".";
	net_read_fatal = 1;
	netnwrite_msg = "451 4.3.0 error writing mail to queue\r\n";
	log_write_msg = "broken pipe to qmail-queue";
	log_write_priority = LOG_ERR;

	close(fd0[0]);

	r = smtp_data();

	if (r != EDONE)
		ret++;

	close(fd0[1]);

	return ret;
}

static int
check_data_body(void)
{
#define RCVDHDR "Received: from unknown ([::ffff:192.0.2.24])\n" \
		"\tby testcase.example.net (" VERSIONSTRING ") with SMTP\n" \
		"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n"
#define RCVDDUMMYLINE "Received: dummy"
#define FOOLINE "X-foobar: yes"
#define FOOHDR FOOLINE "\n"

	int ret = 0;
	const char *endline[] = { ".", NULL };
	const char *twolines[] = { "", ".", NULL };
	const char *twolines_xfoobar[] = { FOOLINE, ".", NULL };
	const char *date_hdr[] = { "Date: Wed, 11 Apr 2012 18:32:17 +0200", "", ".", NULL };
	const char *from_hdr[] = { "From: <foo@example.com>", ".", NULL };
	const char *date2_hdr[] = { date_hdr[0], date_hdr[0], "", ".", NULL };
	const char *from2_hdr[] = { from_hdr[0], from_hdr[0], "", ".", NULL };
	const char *minimal_hdr[] = { date_hdr[0], from_hdr[0], ".", NULL };
	const char *body8bit[] = { date_hdr[0], from_hdr[0], "", "\222", ".", NULL };
	const char *more_msgid[] = { "Message-Id: <123@example.net>", ".", NULL };
	const char *dotline[] = { "..", "...", "....", ".", NULL };
	const char *received_ofl[MAXHOPS + 3];
	char rcvdbuf[strlen(RCVDHDR) + MAXHOPS * (strlen(RCVDDUMMYLINE) + 1) + 16];
	struct {
		const char *name;
		const char *data_expect;
		const char *netmsg;
		const char **netmsg_more;
		const char *logmsg;
		const char *netwrite_msg;
		unsigned long maxlen;
		unsigned long msgsize;
		int check2822_flags;
		int data_result;
	} testdata[] = {
		{
			.name = "empty message",
			.data_expect = RCVDHDR
		},
		{
			.name = "single line",
			.data_expect = RCVDHDR
				FOOHDR,
			.netmsg = FOOLINE,
			.maxlen = 512,
			.msgsize = 15
		},
		{
			.name = "x-foobar header",
			.data_expect = RCVDHDR
				FOOHDR
				"\n",
			.netmsg = FOOLINE,
			.netmsg_more = twolines,
			.maxlen = 512,
			.msgsize = 15
		},
		{
			.name = "x-foobar body",
			.data_expect = RCVDHDR
				"\n"
				FOOHDR,
			.netmsg = "",
			.netmsg_more = twolines_xfoobar,
			.maxlen = 512,
			.msgsize = 15
		},
		{
			.name = "minimal valid header",
			.data_expect = RCVDHDR
				FOOHDR
				"Date: Wed, 11 Apr 2012 18:32:17 +0200\n"
				"From: <foo@example.com>\n",
			.netmsg = FOOLINE,
			.netmsg_more = minimal_hdr,
			.maxlen = 512,
			.msgsize = 79,
			.check2822_flags = 1
		},
		{
			.name = "submission mode headers inserted",
			.data_expect = RCVDHDR
				FOOHDR
				"Message-Id: <123@example.net>\n"
				"Date: Wed, 11 Apr 2012 18:32:17 +0200\n"
				"From: <foo@example.com>\n",
			.netmsg = FOOLINE,
			.netmsg_more = more_msgid,
			.maxlen = 512,
			.msgsize = 46, // the extra lines that are automatically inserted are not counted
			.check2822_flags = 2
		},
		{
			.name = "submission mode all headers inserted",
			.data_expect = RCVDHDR
				FOOHDR
				"Date: Wed, 11 Apr 2012 18:32:17 +0200\n"
				"From: <foo@example.com>\n"
				"Message-Id: <1334161937.10203042@msgid.example.net>\n",
			.netmsg = FOOLINE,
			.maxlen = 512,
			.msgsize = strlen(FOOHDR) + 1, // the extra lines that are automatically inserted are not counted
			.check2822_flags = 2
		},
		{
			.name = "leading data dot",
			.data_expect = RCVDHDR
				FOOHDR
				".\n..\n...\n",
			.netmsg = FOOLINE,
			.netmsg_more = dotline,
			.maxlen = 512,
			.msgsize = 27
		},
		{
			.name = "message too big",
			.data_expect = RCVDHDR
				FOOHDR,
			.logmsg = "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (27 bytes) {message too big}",
			.netmsg = FOOLINE,
			.netmsg_more = dotline,
			.maxlen = 1,
			.data_result = EMSGSIZE
		},
		{
			.name = "822 missing From:",
			.data_expect = RCVDHDR
				FOOHDR
				"Date: Wed, 11 Apr 2012 18:32:17 +0200\n",
			.netmsg = FOOLINE,
			.netmsg_more = date_hdr,
			.netwrite_msg = "550 5.6.0 message does not comply to RfC2822: 'From:' missing\r\n",
			.logmsg = "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (56 bytes) {no 'From:' in header}",
			.maxlen = 512,
			.check2822_flags = 1,
			.data_result = EDONE
		},
		{
			.name = "822 missing Date:",
			.data_expect = RCVDHDR
				FOOHDR
				"From: <foo@example.com>\n",
			.netmsg = FOOLINE,
			.netmsg_more = from_hdr,
			.netwrite_msg = "550 5.6.0 message does not comply to RfC2822: 'Date:' missing\r\n",
			.logmsg = "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (40 bytes) {no 'Date:' in header}",
			.maxlen = 512,
			.check2822_flags = 1,
			.data_result = EDONE
		},
		{
			.name = "822 duplicate From:",
			.data_expect = RCVDHDR
				FOOHDR
				"From: <foo@example.com>\n",
			.netmsg = FOOLINE,
			.netmsg_more = from2_hdr,
			.netwrite_msg = "550 5.6.0 message does not comply to RfC2822: more than one 'From:'\r\n",
			.logmsg = "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (67 bytes) {more than one 'From:' in header}",
			.maxlen = 512,
			.check2822_flags = 1,
			.data_result = EDONE
		},
		{
			.name = "822 duplicate Date:",
			.data_expect = RCVDHDR
				FOOHDR
				"Date: Wed, 11 Apr 2012 18:32:17 +0200\n",
			.netmsg = FOOLINE,
			.netmsg_more = date2_hdr,
			.netwrite_msg = "550 5.6.0 message does not comply to RfC2822: more than one 'Date:'\r\n",
			.logmsg = "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (95 bytes) {more than one 'Date:' in header}",
			.maxlen = 512,
			.check2822_flags = 1,
			.data_result = EDONE
		},
		{
			.name = "8bit data in header",
			.data_expect = RCVDHDR,
			.netmsg = body8bit[3],
			.netwrite_msg = "550 5.6.0 message does not comply to RfC2822: 8bit character in message header\r\n",
			.logmsg = "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (3 bytes) {8bit-character in message header}",
			.maxlen = 512,
			.check2822_flags = 1,
			.data_result = EDONE
		},
		{
			.name = "8bit data in body",
			.data_expect = RCVDHDR
				FOOHDR
				"Date: Wed, 11 Apr 2012 18:32:17 +0200\n"
				"From: <foo@example.com>\n\n",
			.netmsg = FOOLINE,
			.netmsg_more = body8bit,
			.netwrite_msg = "550 5.6.0 message contains 8bit characters\r\n",
			.logmsg = "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (82 bytes) {8bit-character in message body}",
			.maxlen = 512,
			.check2822_flags = 1,
			.data_result = EDONE
		},
		{
			.name = "too many received lines",
			.data_expect = rcvdbuf,
			.netmsg = RCVDDUMMYLINE,
			.netmsg_more = received_ofl,
			.netwrite_msg = "554 5.4.6 too many hops, this message is looping\r\n",
			.logmsg = "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (1719 bytes) {mail loop}",
			.maxlen = MAXHOPS * 17 + 256,
			.data_result = EDONE
		},
		{
			.name = "Delivered-To: loop",
			.data_expect = RCVDHDR,
			.netmsg = "Delivered-To: test@example.com",
			.netmsg_more = twolines,
			.netwrite_msg = "554 5.4.6 message is looping, found a \"Delivered-To:\" line with one of the recipients\r\n",
			.logmsg = "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (34 bytes) {mail loop}",
			.maxlen = MAXHOPS * 17 + 256,
			.data_result = EDONE
		},
		{
			.name = NULL
		}
	};

	printf("%s\n", __func__);

	testcase_setup_netnwrite(test_netnwrite);

	memset(&xmitstat, 0, sizeof(xmitstat));
	badbounce = 0;
	goodrcpt = 1;
	relayclient = 1;
	xmitstat.mailfrom.s = "foo@example.com";
	xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);
	strncpy(xmitstat.remoteip, "::ffff:192.0.2.24", sizeof(xmitstat.remoteip));

	int fd0[2];
	int r = setup_datafd(fd0);
	if (r != 0)
		return r;

	snprintf(rcvdbuf, sizeof(rcvdbuf), "%s", RCVDHDR);
	for (r = 0; r < MAXHOPS; r++) {
		received_ofl[r] = RCVDDUMMYLINE;
		strcat(rcvdbuf, RCVDDUMMYLINE "\n");
	}
	received_ofl[r++] = "";
	received_ofl[r++] = ".";
	received_ofl[r] = NULL;

	for (unsigned int idx = 0; testdata[idx].name != NULL; idx++) {
		printf("%s: checking '%s'\n", __func__, testdata[idx].name);

		if (testdata[idx].netmsg) {
			expect_queue_envelope = strlen(testdata[idx].netmsg) + 2;
			net_read_msg = testdata[idx].netmsg;
			if (testdata[idx].netmsg_more)
				net_read_msg_next = testdata[idx].netmsg_more;
			else
				net_read_msg_next = endline;
		} else {
			net_read_msg = endline[0];
		}
		log_write_msg = testdata[idx].logmsg;
		log_write_priority = LOG_INFO;
		expect_queue_envelope = testdata[idx].msgsize;
		net_read_fatal = 1;
		queue_init_result = 0;
		queue_reset_expected = 1;
		pass_354 = 1;
		maxbytes = testdata[idx].maxlen;
		xmitstat.check2822 = testdata[idx].check2822_flags & 1;
		submission_mode = testdata[idx].check2822_flags & 2 ? 1 : 0;
		netnwrite_msg = testdata[idx].netwrite_msg;
		if (idx > 0) {
			int s;

			// the error tests close the datafd, in that case reopen it
			if (queuefd_data < 0) {
				close(fd0[0]);
				s = setup_datafd(fd0);
			}
			else
				s = setup_recip();
			if (s != 0)
				return s;
		}

		r = smtp_data();

		if (r != testdata[idx].data_result)
			ret++;

		if (check_msgbody(testdata[idx].data_expect, fd0[0]) != 0)
			ret++;

		if (testcase_netnwrite_check(testdata[idx].name)) {
			ret++;
			fprintf(stderr, "ERROR: network data pending at end of test\n");
		}
	}

	close(fd0[0]);
	close(fd0[1]);

	return ret;
}

#ifdef CHUNKING
static int
check_bdat_badbounce(void)
{
	int ret = 0;

	printf("%s\n", __func__);
	netnwrite_msg = "554 5.1.1 no valid recipients\r\n";
	badbounce = 1;
	goodrcpt = 1;

	int r = smtp_bdat();

	if (r != EDONE)
		ret++;

	ret += testcase_netnwrite_check(__func__);

	return ret;
}

static int
check_bdat_no_rcpt(void)
{
	int ret = 0;

	printf("%s\n", __func__);
	netnwrite_msg = "554 5.1.1 no valid recipients\r\n";
	badbounce = 0;
	goodrcpt = 0;

	int r = smtp_bdat();

	if (r != EDONE)
		ret++;

	ret += testcase_netnwrite_check(__func__);

	return ret;
}

static int
check_bdat_invalid_args(void)
{
	int ret = 0;
	unsigned int i = 0;
	char longintbuf[32];
	const char *inputs[] = { "#123", "abc", "42 x", longintbuf, NULL };

	printf("%s\n", __func__);
	badbounce = 0;
	goodrcpt = 1;
	snprintf(longintbuf, sizeof(longintbuf), "42%llu", ULONG_LONG_MAX);

	for (i = 0; inputs[i] != NULL; i++) {
		sprintf(linein.s, "BDAT %s", inputs[i]);
		linein.len = strlen(linein.s);

		int r = smtp_bdat();

		if (r != EINVAL)
			ret++;

		ret += testcase_netnwrite_check(__func__);
	}

	return ret;
}

static int
check_bdat_qinit_fail(void)
{
	int ret = 0;

	printf("%s\n", __func__);
	badbounce = 0;
	goodrcpt = 1;
	queue_init_result = EDONE;
	comstate = 0x0040;

	strcpy(linein.s, "BDAT 0");
	linein.len = strlen(linein.s);

	int r = smtp_bdat();

	if (r != EDONE)
		ret++;

	return ret;
}

static int
check_bdat_empty_chunks(void)
{
	int ret = 0;

	printf("%s\n", __func__);
	badbounce = 0;
	goodrcpt = 1;
	queue_init_result = 0;
	comstate = 0x0040;
	xmitstat.esmtp = 1;

	int fd0[2];
	setup_datafd(fd0);

	for (int i = 0; i < 3; i++) {
		strcpy(linein.s, "BDAT 0");
		linein.len = strlen(linein.s);
		netnwrite_msg = "250 2.5.0 0 octets received\r\n";

		int r = smtp_bdat();

		if (r != 0)
			ret++;

		if (comstate != 0x0800)
			ret++;
	}

	strcpy(linein.s, "BDAT 0 LAST");
	linein.len = strlen(linein.s);

	int r = smtp_bdat();

	if (r != 0)
		ret++;

	if (comstate != 0x0800)
		ret++;

	if (check_msgbody("Received: from unknown ([::ffff:192.0.2.24])\n"
			"\tby testcase.example.net (" VERSIONSTRING ") with (chunked) ESMTP\n"
			"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n", fd0[0]) != 0)
		ret++;

	close(fd0[0]);
	close(fd0[1]);

	return ret;
}
#endif

int main()
{
	int ret = 0;
	/* Block SIGPIPE, otherwise the process will get killed when trying to
	 * read from a socket where the remote end was closed. */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGPIPE);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		int e = errno;
		fprintf(stderr, "Cannot block SIGPIPE, error %i\n", e);
		return e;
	}

	memset(&xmitstat, 0, sizeof(xmitstat));
	msgidhost.s = "msgid.example.net";
	msgidhost.len = strlen(msgidhost.s);

	testcase_setup_netnwrite(testcase_netnwrite_compare);

	socketd = 1;

	ret += check_twodigit();
	ret += check_date822();
	ret += check_queueheader();
	ret += check_check_rfc822_headers();
	ret += check_data_badbounce();
	ret += check_data_no_rcpt();
	ret += check_data_qinit_fail();

	testcase_setup_netnwrite(test_netnwrite);

	ret += check_data_354_fail();

	testcase_setup_net_read(testcase_net_read_simple);
	testcase_setup_log_writen(testcase_log_writen_combine);
	testcase_setup_log_write(testcase_log_write_compare);

	ret += check_data_write_received_fail();
	ret += check_data_write_received_pipefail();
	ret += check_data_body();

#ifdef CHUNKING
	ssl = NULL;

	ret += check_bdat_badbounce();
	ret += check_bdat_no_rcpt();
	ret += check_bdat_invalid_args();
	ret += check_bdat_qinit_fail();

	expect_queue_chunked = 1;
	testcase_setup_net_writen(testcase_net_writen_combine);

	ret += check_bdat_empty_chunks();
#endif

	return ret;
}
