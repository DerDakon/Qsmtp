#ifndef CHUNKING
#define CHUNKING
#endif
#define INCOMING_CHUNK_SIZE 2
#include "../qsmtpd/data.c"

#include <qsmtpd/antispam.h>
#include "test_io/testcase_io.h"
#include <version.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int relayclient;
unsigned long sslauth;
unsigned long databytes;
unsigned int goodrcpt;
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
struct rcpt_list head;

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
#if defined(__DARWIN_ONLY_UNIX_CONFORMANCE) || defined(__NetBSD__)
gettimeofday(struct timeval *tv, void *tz)
#else
gettimeofday(struct timeval *tv, struct timezone *tz)
#endif
{
	assert(tv);
	if ((tz != NULL)
#if !defined(__DARWIN_ONLY_UNIX_CONFORMANCE) && !defined(__NetBSD__)
		&& ((tz->tz_dsttime != 0) || (tz->tz_minuteswest != 0))
#endif
		)
		abort();

	tv->tv_sec = time(NULL);
	tv->tv_usec = 10203042;

	return 0;
}

static SSL *dummy_ssl = ((SSL*)(uintptr_t)0xabcdcafe);
static SSL_CIPHER *dummy_cipher = ((SSL_CIPHER*)(uintptr_t)0xdeadabcd);
#define DUMMY_CIPHER_STRING "<OPENSSL_CIPHER_STRING_DUMMY>"

const SSL_CIPHER *
SSL_get_current_cipher(const SSL *s)
{
	if (s != dummy_ssl)
		abort();

	return dummy_cipher;
}

const char *
SSL_CIPHER_get_name(const SSL_CIPHER *c)
{
	if (c != dummy_cipher)
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
		abort();
	queue_reset_expected = 0;

	if (queuefd_data >= 0) {
		close(queuefd_data);
		queuefd_data = -1;
	}
	if (queuefd_hdr >= 0) {
		close(queuefd_hdr);
		queuefd_hdr = -1;
	}
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
		abort();
	}
}

static unsigned long expect_queue_envelope = -1;
static unsigned int expect_queue_result;
static int queue_envelope_error;
static int expect_queue_chunked;
static int queuefd_data_recv = -1; // receiving end of the data pipe

int
queue_envelope(const unsigned long sz, const int chunked)
{
	if (expect_queue_envelope == (unsigned long)-1)
		abort();

	if (sz != expect_queue_envelope) {
		fprintf(stderr, "%s(%lu, %i) called, but (%lu, %i) expected\n", __func__, sz, chunked, expect_queue_envelope, expect_queue_chunked);
		abort();
	}

	if (chunked != expect_queue_chunked) {
		fprintf(stderr, "%s(%lu, %i) called, but (%lu, %i) expected\n", __func__, sz, chunked, expect_queue_envelope, expect_queue_chunked);
		abort();
	}

	expect_queue_envelope = -1;

	if (queue_envelope_error) {
		errno = queue_envelope_error;
		queue_envelope_error = -1;
		return -1;
	}

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
	close(queuefd_data);

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

static struct cstring *readbin_data;
static size_t readbin_data_pos;

size_t
test_net_readbin(size_t a, char *b)
{
	if (readbin_data == NULL)
		abort();

	if (a == 0)
		abort();

	size_t ret = readbin_data->len - readbin_data_pos;
	if (a < ret)
		ret = a;
	memcpy(b, readbin_data->s + readbin_data_pos, ret);

	readbin_data_pos += ret;
	if (readbin_data_pos == readbin_data->len) {
		readbin_data = NULL;
		readbin_data_pos = 0;
	}

	return ret;
}

static unsigned int readbin_expected;

size_t
test_net_readbin_err(size_t a __attribute__((unused)), char *b __attribute__((unused)))
{
	if (readbin_expected == 0)
		abort();

	readbin_expected--;

	errno = 1234;
	return -1;
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
setup_datafd(void)
{
	int fd0[2];

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

	int r = setup_recip();
	if (r != 0) {
		close(fd0[0]);
		close(fd0[1]);
		return r;
	}

	if (queuefd_data_recv >= 0) {
		r = close(queuefd_data_recv);
		if (r != 0)
			abort();
		queuefd_data_recv = -1;
	}

	queuefd_data = fd0[1];
	queuefd_data_recv = fd0[0];

	return 0;
}

static int
check_msgbody(const char *expect)
{
	int err = 0;
	size_t off = 0;
	ssize_t mismatch = -1;
	char outbuf[CHUNK_READ_SIZE * 4];
	static const char received_from[] = "Received: from ";

	while (off < sizeof(outbuf) - 1) {
		const ssize_t r = read(queuefd_data_recv, outbuf + off, 1);
		if (r < 0) {
			if (errno != EAGAIN) {
				fprintf(stderr, "read failed with error %i\n", errno);
				return 5;
			}
			break;
		}
		if (r == 0)
			break;
		if ((mismatch < 0) && (off < strlen(expect)) && (outbuf[off] != expect[off])) {
			mismatch = off;
			unsigned char e = expect[off];
			unsigned char o = outbuf[off];
			char ech = iscntrl(e) ? '?' : e;
			char och = iscntrl(o) ? '?' : o;
			fprintf(stderr, "output mismatch at position %zi, got %c (0x%02x), expected %c (0x%02x)\n",
				mismatch, och, o, ech, e);
			err = 6;
			// do not break, read the whole input
		}
		off++;
	}
	outbuf[off] = '\0';

	if ((err != 0) || (off != strlen(expect))) {
		if (memcmp(outbuf, expect, strlen(expect)) != 0)
			fprintf(stderr, "expected output not found, got:\n%s\nexpected:\n%s\n", outbuf, expect);
		if (off != strlen(expect))
			fprintf(stderr, "expected length: %zu, got length: %zu\n", strlen(expect), off);
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
	int err = setup_datafd();

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
			ssl = dummy_ssl;
			expect = "Received: from unknown ([192.0.2.42])\n"
					"\tby testcase.example.net (" VERSIONSTRING ") with (" DUMMY_CIPHER_STRING " encrypted) ESMTPS\n"
					"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n";
			break;
		case 15:
			/* plain SSL mail */
			testname = "SSL chunked";
			relayclient = 1;
			ssl = dummy_ssl;
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

		err = check_msgbody(expect);
		if (err != 0)
			break;
	}

	struct recip *l = TAILQ_FIRST(&head);

	TAILQ_REMOVE(&head, TAILQ_FIRST(&head), entries);
	free(l->to.s);
	free(l);
	thisrecip = NULL;
	if (!TAILQ_EMPTY(&head))
		abort();

	/* pass invalid fd in, this should cause the write() to fail */
	close(queuefd_data);
	queuefd_data = -1;
	close(queuefd_data_recv);
	queuefd_data_recv = -1;

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
		{ }
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
check_data_no_rcpt(void)
{
	int ret = 0;

	printf("%s\n", __func__);
	netnwrite_msg = "554 5.1.1 no valid recipients\r\n";
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
	int r = setup_datafd();

	printf("%s\n", __func__);

	if (r != 0)
		return r;

	goodrcpt = 1;
	queue_init_result = 0;
	queue_reset_expected = 1;
	pass_354 = 1;
	net_read_msg = ".";
	net_read_fatal = 1;
	netnwrite_msg = "451 4.3.0 error writing mail to queue\r\n";
	log_write_msg = "broken pipe to qmail-queue";
	log_write_priority = LOG_ERR;

	close(queuefd_data_recv);

	r = smtp_data();

	if (r != EDONE)
		ret++;

	queuefd_data_recv = -1;

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
	const char *delivered[] = { "Delivered-To: test@example.com", ".", NULL };
	const char *received_ofl[MAXHOPS + 3];
	char rcvdbuf[strlen(RCVDHDR) + MAXHOPS * (strlen(RCVDDUMMYLINE) + 1) + 16];
	char rcvdbuf_body[sizeof(rcvdbuf) + 4];
	struct {
		const char *name;
		const char *data_expect;
		const char *netmsg;
		const char **netmsg_more;
		const char *logmsg;
		const char *netwrite_msg;
		unsigned long maxlen;
		unsigned int check2822_flags:2;
		unsigned int hdrfd:1;
		unsigned int queue_expect:1;
		int data_result:16;
	} testdata[] = {
		{
			.name = "empty message",
			.data_expect = RCVDHDR,
			.queue_expect = 1
		},
		{
			.name = "single line",
			.data_expect = RCVDHDR
				FOOHDR,
			.netmsg = FOOLINE,
			.maxlen = 512,
			.queue_expect = 1
		},
		{
			.name = "x-foobar header",
			.data_expect = RCVDHDR
				FOOHDR
				"\n",
			.netmsg = FOOLINE,
			.netmsg_more = twolines,
			.maxlen = 512,
			.queue_expect = 1
		},
		{
			.name = "x-foobar body",
			.data_expect = RCVDHDR
				"\n"
				FOOHDR,
			.netmsg = "",
			.netmsg_more = twolines_xfoobar,
			.maxlen = 512,
			.queue_expect = 1
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
			.queue_expect = 1,
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
			.check2822_flags = 2,
			.queue_expect = 1 // the extra lines that are automatically inserted are not counted
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
			.check2822_flags = 2,
			.queue_expect = 1 // the extra lines that are automatically inserted are not counted
		},
		{
			.name = "leading data dot",
			.data_expect = RCVDHDR
				FOOHDR
				".\n..\n...\n",
			.netmsg = FOOLINE,
			.netmsg_more = dotline,
			.maxlen = 512,
			.queue_expect = 1
		},
		{
			.name = "message too big",
			.data_expect = RCVDHDR
				FOOHDR,
			.logmsg = "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (27 bytes) {message too big}",
			.netmsg = FOOLINE,
			.netmsg_more = dotline,
			.maxlen = 1,
			.hdrfd = 1,
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
			.hdrfd = 1,
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
			.hdrfd = 1,
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
			.hdrfd = 1,
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
			.hdrfd = 1,
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
			.hdrfd = 1,
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
			.logmsg = "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (84 bytes) {8bit-character in message body}",
			.maxlen = 512,
			.check2822_flags = 1,
			.hdrfd = 1,
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
			.hdrfd = 1,
			.data_result = EDONE
		},
		{
			.name = "Delivered-To: loop",
			.data_expect = RCVDHDR,
			.netmsg = delivered[0],
			.netmsg_more = twolines,
			.netwrite_msg = "554 5.4.6 message is looping, found a \"Delivered-To:\" line with one of the recipients\r\n",
			.logmsg = "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (34 bytes) {mail loop}",
			.maxlen = MAXHOPS * 17 + 256,
			.hdrfd = 1,
			.data_result = EDONE
		},
		{
			.name = "received lines in body",
			.data_expect = rcvdbuf_body,
			.netmsg = "",
			.netmsg_more = received_ofl,
			.maxlen = MAXHOPS * 17 + 256,
			.queue_expect = 1
		},
		{
			.name = "body with Delivered-To:",
			.data_expect = RCVDHDR
				"\n"
				"Delivered-To: test@example.com\n",
			.netmsg = "",
			.netmsg_more = delivered,
			.maxlen = 256,
			.queue_expect = 1
		},
		{ }
	};

	printf("%s\n", __func__);

	testcase_setup_netnwrite(test_netnwrite);

	memset(&xmitstat, 0, sizeof(xmitstat));
	goodrcpt = 1;
	relayclient = 1;
	xmitstat.mailfrom.s = "foo@example.com";
	xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);
	strncpy(xmitstat.remoteip, "::ffff:192.0.2.24", sizeof(xmitstat.remoteip));

	int r;
	snprintf(rcvdbuf, sizeof(rcvdbuf), "%s", RCVDHDR);
	snprintf(rcvdbuf_body, sizeof(rcvdbuf), "%s\n", RCVDHDR);
	for (r = 0; r < MAXHOPS; r++) {
		received_ofl[r] = RCVDDUMMYLINE;
		strcat(rcvdbuf, RCVDDUMMYLINE "\n");
		strcat(rcvdbuf_body, RCVDDUMMYLINE "\n");
	}
	received_ofl[r++] = "";
	received_ofl[r++] = ".";
	received_ofl[r] = NULL;
	strcat(rcvdbuf_body, "\n");

	for (unsigned int idx = 0; testdata[idx].name != NULL; idx++) {
		printf("%s: checking '%s'\n", __func__, testdata[idx].name);
		size_t msglen = 0;

		if (testdata[idx].netmsg) {
			net_read_msg = testdata[idx].netmsg;
			if (testdata[idx].netmsg_more)
				net_read_msg_next = testdata[idx].netmsg_more;
			else
				net_read_msg_next = endline;

			for (r = 0; net_read_msg_next[r] != NULL; r++) {
				msglen += strlen(net_read_msg_next[r]) + 2;
				if (net_read_msg_next[r][0] == '.')
					msglen--;
			}
			// + 2 for CRLF - 2 for "." line
			msglen += strlen(net_read_msg);
		} else {
			net_read_msg = endline[0];
		}
		log_write_msg = testdata[idx].logmsg;
		log_write_priority = LOG_INFO;
		if (testdata[idx].queue_expect)
			expect_queue_envelope = msglen;
		else
			expect_queue_envelope = (unsigned long)-1;
		net_read_fatal = 1;
		queue_init_result = 0;
		queue_reset_expected = 1;
		pass_354 = 1;
		maxbytes = testdata[idx].maxlen;
		xmitstat.check2822 = testdata[idx].check2822_flags & 1;
		submission_mode = testdata[idx].check2822_flags & 2 ? 1 : 0;
		netnwrite_msg = testdata[idx].netwrite_msg;
		if (testdata[idx].hdrfd)
			queuefd_hdr = open("/dev/null", O_WRONLY);
		else
			queuefd_hdr = -1;

		// the error tests close the datafd, in that case reopen it
		r = setup_datafd();
		if (r != 0)
			return r;

		r = smtp_data();

		if (r != testdata[idx].data_result)
			ret++;

		if (check_msgbody(testdata[idx].data_expect) != 0)
			ret++;

		if (testcase_netnwrite_check(testdata[idx].name)) {
			ret++;
			fprintf(stderr, "ERROR: network data pending at end of test\n");
		}

		if (expect_queue_envelope != (unsigned long)-1)
			ret++;

		freedata();
	}

	if (queuefd_data_recv >= 0) {
		close(queuefd_data_recv);
		queuefd_data_recv = -1;
	}
	if (queuefd_data >= 0) {
		close(queuefd_data);
		queuefd_data = -1;
	}
	expect_queue_envelope = -1;

	return ret;
}

// simulate error return codes from net_read()
// if the current read string has the form "#<error code>" then the given error code
// is returned instead of success
int
test_net_read_error(const int fatal)
{
	int r = testcase_net_read_simple(fatal);

	if ((r == 0) && (linein.len > 0) && (linein.s[0] == '#')) {
		if (strcmp(linein.s + 1, "EINVAL") == 0) {
			errno = EINVAL;
			r = -1;
		} else if (strcmp(linein.s + 1, "E2BIG") == 0) {
			errno = E2BIG;
			r = -1;
		} else {
			abort();
		}
		linein.len = 0;
	}

	return r;
}

static int
check_data_read_fails(void)
{
	int ret = 0;

	printf("%s\n", __func__);
	testcase_setup_net_read(test_net_read_error);

	for (unsigned int i = 0; ; i++) {
		const char *msgs[] = { "X-header: foo", "X-header: bar", "", "", "body 1", "body 2", ".", NULL };
		unsigned int msglen = 0;
		char logbuf[160];

		if (msgs[i][0] == '.')
			break;

		int r = setup_datafd();
		if (r != 0)
			return r;

		for (unsigned int j = 0; msgs[j] != NULL; j++) {
			if (i == j)
				msgs[j] = "#EINVAL";
			else
				msglen += strlen(msgs[j]) + 2;
		}
		msglen--; // "."

		net_read_msg = "";
		net_read_msg_next = msgs;
		net_read_fatal = 1;

		// let the testcase function do the rotation so the first buffer entry is set
		testcase_net_read_simple(net_read_fatal);

		snprintf(logbuf, sizeof(logbuf), "rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (%u bytes) {bad CRLF sequence}", msglen);
		log_write_msg = logbuf;
		log_write_priority = LOG_INFO;
		queue_init_result = 0;
		queue_reset_expected = 1;
		pass_354 = 1;
		maxbytes = 256;
		netnwrite_msg = "500 5.5.2 bad <CRLF> sequence\r\n";
		queuefd_hdr = open("/dev/null", O_WRONLY);

		r = smtp_data();

		if (r != EDONE)
			ret++;

		if (testcase_netnwrite_check(__func__)) {
			ret++;
			fprintf(stderr, "ERROR: network data pending at end of test loop %u\n", i);
		}
	}

	testcase_setup_net_read(testcase_net_read_simple);

	return ret;
}

static int
check_bdat_no_rcpt(void)
{
	int ret = 0;

	printf("%s\n", __func__);
	netnwrite_msg = "554 5.1.1 no valid recipients\r\n";
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
	goodrcpt = 1;
	snprintf(longintbuf, sizeof(longintbuf), "42%" PRIu64, UINT64_MAX);

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
	goodrcpt = 1;
	queue_init_result = 0;
	comstate = 0x0040;
	xmitstat.esmtp = 1;
	expect_queue_envelope = 0;

	setup_datafd();

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
			"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n") != 0)
		ret++;

	close(queuefd_data_recv);
	queuefd_data_recv = -1;

	if (expect_queue_envelope != (unsigned long)-1)
		ret++;

	return ret;
}

static int
check_bdat_single_chunk(void)
{
#define MIMELINE "MIME-Version: 1.0"
#define RCVDHDRCHUNKED "Received: from unknown ([::ffff:192.0.2.24])\n" \
		"\tby testcase.example.net (" VERSIONSTRING ") with (chunked) ESMTP\n" \
		"\tfor <test@example.com>; Wed, 11 Apr 2012 18:32:17 +0200\n"
	int ret = 0;
	struct {
		const char *name;
		const char *input;
		const char *expect;
	} patterns[] = {
		{
			.name = "one line CRLF",
			.input = FOOLINE "\r\n",
			.expect = RCVDHDRCHUNKED
				FOOLINE "\n"
		},
		{
			.name = "one line LF",
			.input = FOOLINE "\n",
			.expect = RCVDHDRCHUNKED
				FOOLINE "\n"
		},
		{
			.name = "one line no LF",
			.input = FOOLINE,
			.expect = RCVDHDRCHUNKED
				FOOLINE
		},
		{
			.name = "two lines CRLF",
			.input = FOOLINE "\r\n" MIMELINE "\r\n",
			.expect = RCVDHDRCHUNKED
				FOOLINE "\n"
				MIMELINE "\n"
		},
		{
			.name = "two lines LF",
			.input = FOOLINE "\n" MIMELINE "\n",
			.expect = RCVDHDRCHUNKED
				FOOLINE "\n"
				MIMELINE "\n"
		},
		{
			.name = "one line LF one line CRLF",
			.input = FOOLINE "\n" MIMELINE "\r\n",
			.expect = RCVDHDRCHUNKED
				FOOLINE "\n"
				MIMELINE "\n"
		},
		{
			.name = "one line CRLF one line LF",
			.input = FOOLINE "\r\n" MIMELINE "\n",
			.expect = RCVDHDRCHUNKED
				FOOLINE "\n"
				MIMELINE "\n"
		},
		{
			.name = "one line CR",
			.input = FOOLINE "\r",
			.expect = RCVDHDRCHUNKED
				FOOLINE "\r"
		},
		{
			.name = "two lines CR",
			.input = FOOLINE "\r" FOOLINE "\r",
			.expect = RCVDHDRCHUNKED
				FOOLINE "\r"
				FOOLINE "\r"
		},
		{ }
	};

	printf("%s\n", __func__);
	maxbytes = 16 * 1024;

	for (unsigned int j = 0; patterns[j].name != NULL; j++) {
		struct cstring bindata = {
			.s = patterns[j].input,
			.len = strlen(patterns[j].input)
		};

		printf("Testing %s\n", patterns[j].name);
		goodrcpt = 1;
		queue_init_result = 0;
		comstate = 0x0040;
		xmitstat.esmtp = 1;
		readbin_data = &bindata;
		expect_queue_envelope = bindata.len;
		expect_queue_chunked = 1;

		setup_datafd();

		sprintf(linein.s, "BDAT %zu LAST", bindata.len);
		linein.len = strlen(linein.s);

		int r = smtp_bdat();

		if (r != 0)
			ret++;

		if (comstate != 0x0800)
			ret++;

		if (testcase_netnwrite_check(__func__))
			ret++;

		if (check_msgbody(patterns[j].expect) != 0)
			ret++;

		close(queuefd_data_recv);
		queuefd_data_recv = -1;
	}

	return ret;
}

static int
check_bdat_readerror(void)
{
	int ret = 0;

	printf("%s\n", __func__);

	testcase_setup_net_readbin(test_net_readbin_err);

	goodrcpt = 1;
	queue_init_result = 0;
	comstate = 0x0040;
	xmitstat.esmtp = 1;
	readbin_expected = 1;
	queue_reset_expected = 1;
	queuefd_hdr = open("/dev/null", O_WRONLY);
	if (queuefd_hdr < 0)
		abort();

	setup_datafd();

	sprintf(linein.s, "BDAT 42 LAST");
	linein.len = strlen(linein.s);

	int r = smtp_bdat();

	if (r != 1234)
		ret++;

	if (comstate != 0x0800)
		ret++;

	if (check_msgbody(RCVDHDRCHUNKED) != 0)
		ret++;

	if (testcase_netnwrite_check(__func__))
		ret++;

	// Ignore the message body here, it will usually contain the received line and
	// the beginning of the mail, but it is totally irrelevant what is in there.

	close(queuefd_data_recv);
	queuefd_data_recv = -1;

	return ret;
}

static int
check_bdat_msgsize(void)
{
	int ret = 0;
	struct cstring d = {
		.s = FOOLINE,
		.len = strlen(FOOLINE)
	};
	char logbuf[256];

	printf("%s\n", __func__);

	goodrcpt = 1;
	queue_init_result = 0;
	comstate = 0x0040;
	xmitstat.esmtp = 1;
	readbin_expected = 1;
	queue_reset_expected = 1;
	queuefd_hdr = open("/dev/null", O_WRONLY);
	maxbytes = 1;
	readbin_data = &d;
	snprintf(logbuf, sizeof(logbuf),
			"rejected message to <test@example.com> from <foo@example.com> from IP [::ffff:192.0.2.24] (%zu bytes) {message too big}",
			d.len);
	log_write_msg = logbuf;
	log_write_priority = LOG_INFO;
	if (queuefd_hdr < 0)
		abort();

	setup_datafd();

	sprintf(linein.s, "BDAT %zu LAST", d.len);
	linein.len = strlen(linein.s);

	int r = smtp_bdat();

	if (r != EMSGSIZE)
		ret++;

	if (comstate != 0x0800)
		ret++;

	if (testcase_netnwrite_check(__func__))
		ret++;

	close(queuefd_data_recv);
	queuefd_data_recv = -1;

	return ret;
}

// use the same pattern, split at every possible position, the output should be constant
static int
check_bdat_multiple_chunks(void)
{
	const char inpattern[] = "a\rb\nc\r\nA\nB\rC\r\n\r\n\n\rD\nE\nF\rd\re\rf\n";
	const char outpattern[] = RCVDHDRCHUNKED "a\rb\nc\nA\nB\rC\n\n\n\rD\nE\nF\rd\re\rf\n";
	int ret = 0;
	struct cstring bindata = {
		.s = inpattern,
		.len = strlen(inpattern)
	};

	for (size_t i = 1; i <= strlen(inpattern); i++) {
		char msgbuf[64];
		size_t nextpos = 0;

		readbin_data = &bindata;
		readbin_data_pos = 0;
		goodrcpt = 1;
		queue_init_result = 0;
		comstate = 0x0040;
		xmitstat.esmtp = 1;
		expect_queue_envelope = bindata.len;
		expect_queue_chunked = 1;

		setup_datafd();

		printf("%s split: %zu\n", __func__, i);
		sprintf(msgbuf, "250 2.5.0 %zu octets received\r\n", i);

		while (nextpos < strlen(inpattern)) {
			size_t chunksize;

			if (nextpos + i < strlen(inpattern)) {
				chunksize = i;
				sprintf(linein.s, "BDAT %zu", chunksize);
				netnwrite_msg = msgbuf;
			} else {
				chunksize = strlen(inpattern) - readbin_data_pos;
				sprintf(linein.s, "BDAT %zu LAST", chunksize);
			}
			linein.len = strlen(linein.s);

			int r = smtp_bdat();

			if (r != 0)
				ret++;

			if (comstate != 0x0800)
				ret++;

			nextpos += chunksize;
		}

		if (check_msgbody(outpattern) != 0)
			ret++;

		if (testcase_netnwrite_check(__func__))
			ret++;

		if (expect_queue_envelope != (unsigned long)-1)
			ret++;

		close(queuefd_data);
		queuefd_data = -1;
		close(queuefd_data_recv);
		queuefd_data_recv = -1;
	}

	return ret;
}

// Since the trick here is to have multiple buffers and the buffers are large the
// contents are not directly given, but encoded as follows:
// value  meaning  value in input buffer               value in output buffer
// P      padding  (97*whitespace + 'X' + CR + LF)*X   97*whitespace + 'X' + LF
//        [enough to fill up all but 5 byte of the read buffer]
// c      bare CR  CR                                  CR
// l      bare LF  LF                                  LF
// N      CRLF     CR + LF                             LF
// .      dot      .                                   .
static int
run_multibuffer_test(const char *name, const char *pattern)
{
	char inbuf[CHUNK_READ_SIZE * 3];
	char outbuf[sizeof(inbuf) + sizeof(RCVDHDRCHUNKED)];
	struct cstring bindata = {
		.s = inbuf
	};
	int ret = 0;

	inbuf[0] = outbuf[0] = '\0';
	printf("Testing %s\n", name);
	strcat(outbuf, RCVDHDRCHUNKED);

	for (size_t p = 0; p < strlen(pattern); p++) {
		switch (pattern[p]) {
		case 'P':
			{
			char ws[101];
			size_t wpos = strlen(inbuf);
			// position 5 before next buffer break
			size_t endpos = ((wpos + CHUNK_READ_SIZE) / CHUNK_READ_SIZE) * CHUNK_READ_SIZE - 5;

			memset(ws, ' ', sizeof(ws) - 4);
			ws[sizeof(ws) - 4] = 'X';
			ws[sizeof(ws) - 3] = '\r';
			ws[sizeof(ws) - 2] = '\n';
			ws[sizeof(ws) - 1] = '\0';

			while (wpos < endpos - sizeof(ws) - 2) {
				strcat(inbuf, ws);
				strcat(outbuf, ws);
				size_t opos = strlen(outbuf);
				assert(outbuf[opos - 2] == '\r');
				outbuf[opos - 2] = '\n';
				outbuf[opos - 1] = '\0';
				wpos += sizeof(ws) - 1;
			}

			size_t plen;
			// reduce the write
			if (endpos > wpos + 2)
				plen = endpos - wpos;
			else
				plen = 2;
			strncat(inbuf + wpos, ws + sizeof(ws) - 1 - plen, sizeof(inbuf) - wpos - 1);
			ws[sizeof(ws) - 3] = '\n';
			ws[sizeof(ws) - 2] = '\0';
			strncat(outbuf, ws + sizeof(ws) - 1 - plen, sizeof(outbuf) - strlen(outbuf) - 1);

			break;
			}
		case 'c':
			strcat(inbuf, "\r");
			strcat(outbuf, "\r");
			break;
		case 'l':
			strcat(inbuf, "\n");
			strcat(outbuf, "\n");
			break;
		case 'N':
			strcat(inbuf, "\r\n");
			strcat(outbuf, "\n");
			break;
		case '.':
			strcat(inbuf, ".");
			strcat(outbuf, ".");
			break;
		default:
			abort();
		}
	}

	goodrcpt = 1;
	queue_init_result = 0;
	comstate = 0x0040;
	xmitstat.esmtp = 1;
	bindata.len = strlen(bindata.s);
	readbin_data = &bindata;
	expect_queue_envelope = bindata.len;
	expect_queue_chunked = 1;

	setup_datafd();

	sprintf(linein.s, "BDAT %zu LAST", bindata.len);
	linein.len = strlen(linein.s);

	int r = smtp_bdat();

	if (r != 0)
		ret++;

	if (comstate != 0x0800)
		ret++;

	if (testcase_netnwrite_check(__func__))
		ret++;

	if (check_msgbody(outbuf) != 0)
		ret++;

	close(queuefd_data_recv);
	queuefd_data_recv = -1;

	return ret;
}

static int
check_bdat_multiple_buffers(void)
{
	int ret = 0;
	struct {
		const char *name;
		const char *pattern;
	} patterns[] = {
		{
			.name = "multi data buffers",
			.pattern = "PNNNNNPNNNNNP"
		},
		{
			.name = "multi data buffers ending in CR",
			.pattern = "PNNNNNPNNNNNPc"
		},
		{ }
	};

	printf("%s\n", __func__);
	maxbytes = 16 * 1024;

	for (unsigned int j = 0; patterns[j].name != NULL; j++)
		ret += run_multibuffer_test(patterns[j].name, patterns[j].pattern);

	// now shift the CRLF pairs over the buffer limit
	for (unsigned int j = 1; j < 5; j++) {
		const char *shiftpattern[] = {
			"NNNNlPNNNNNP",
			"cNcNlPNNNNNP",
			"ccNllPNNNNNP",
			"NNcNlPNNNNNP",
			NULL
		};

		for (unsigned int l = 0; shiftpattern[l] != NULL; l++) {
			char pbuf[32] = "P";
			char nbuf[32];

			memset(pbuf + 1, '.', j);

			strncpy(pbuf + 1 + j, shiftpattern[l], sizeof(pbuf) - 1 - j);
			snprintf(nbuf, sizeof(nbuf), "pattern %u dot %u", l, j);

			ret += run_multibuffer_test(nbuf, pbuf);
		}
	}

	return ret;
}

static int
check_bdat_write_received_pipefail(void)
{
	int ret = 0;
	struct cstring bindata = {
		.s = "123"
	};
	int r = setup_datafd();

	printf("%s\n", __func__);

	if (r != 0)
		return r;

	goodrcpt = 1;
	queue_init_result = 0;
	queue_reset_expected = 1;
	comstate = 0x0040;
	xmitstat.esmtp = 1;
	bindata.len = strlen(bindata.s);
	readbin_data = &bindata;
	expect_queue_envelope = bindata.len;
	expect_queue_chunked = 1;
	netnwrite_msg = "451 4.3.0 error writing mail to queue\r\n";
	log_write_msg = "broken pipe to qmail-queue";
	log_write_priority = LOG_ERR;

	close(queuefd_data_recv);

	sprintf(linein.s, "BDAT %zu LAST", bindata.len);
	linein.len = strlen(linein.s);

	r = smtp_bdat();

	if (r != EDONE)
		ret++;

	if (comstate != 0x0800)
		ret++;

	if (testcase_netnwrite_check(__func__))
		ret++;

	queuefd_data_recv = -1;

	return ret;
}

static int
check_bdat_write_received_queuefail(void)
{
	int ret = 0;
	struct cstring bindata = {
		.s = "123"
	};
	char logbuf[128];
	int r = setup_datafd();

	printf("%s\n", __func__);

	if (r != 0)
		return r;

	goodrcpt = 1;
	queue_init_result = 0;
	queue_reset_expected = 1;
	comstate = 0x0040;
	xmitstat.esmtp = 1;
	bindata.len = strlen(bindata.s);
	readbin_data = &bindata;
	expect_queue_envelope = bindata.len;
	expect_queue_chunked = 1;
	queue_envelope_error = EFAULT;
	netnwrite_msg = "451 4.3.0 error writing mail to queue\r\n";
	snprintf(logbuf, sizeof(logbuf), "error in BDAT: %s", strerror(queue_envelope_error));
	log_write_msg = logbuf;
	log_write_priority = LOG_ERR;

	sprintf(linein.s, "BDAT %zu LAST", bindata.len);
	linein.len = strlen(linein.s);

	r = smtp_bdat();

	if (r != EDONE)
		ret++;

	if (comstate != 0x0800)
		ret++;

	if (testcase_netnwrite_check(__func__))
		ret++;

	if (check_msgbody(RCVDHDRCHUNKED "123") != 0)
		ret++;

	close(queuefd_data_recv);
	queuefd_data_recv = -1;

	return ret;
}

int
main()
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
	ret += check_data_no_rcpt();
	ret += check_data_qinit_fail();

	testcase_setup_netnwrite(test_netnwrite);

	ret += check_data_354_fail();

	testcase_setup_net_read(testcase_net_read_simple);
	testcase_setup_log_writen(testcase_log_writen_combine);
	testcase_setup_log_write(testcase_log_write_compare);

	ret += check_data_write_received_fail();
	ret += check_data_write_received_pipefail();
	testcase_setup_net_writen(testcase_net_writen_combine);
	ret += check_data_body();

	ret += check_data_read_fails();

	ssl = NULL;

	ret += check_bdat_no_rcpt();
	ret += check_bdat_invalid_args();
	ret += check_bdat_qinit_fail();

	expect_queue_chunked = 1;

	ret += check_bdat_empty_chunks();
	ret += check_bdat_readerror();

	testcase_setup_net_readbin(test_net_readbin);

	ret += check_bdat_msgsize();
	ret += check_bdat_single_chunk();
	ret += check_bdat_multiple_chunks();
	ret += check_bdat_multiple_buffers();

	ret += check_bdat_write_received_pipefail();
	ret += check_bdat_write_received_queuefail();

	return ret;
}
