#include "netio_test_messages.h"

#include <log.h>
#include <netio.h>
#include <tls.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <sys/wait.h>
#include <signal.h>

#ifdef DEBUG_IO
#include "log.h"
void
log_write(int priority __attribute__ ((unused)), const char *s __attribute__ ((unused)))
{
	dieerror(EFAULT);
}
#endif

int socketd;

static const char *testname;
static const char digits[] = "0123456789";

void
dieerror(int error)
{
	fprintf(stderr, "%s: exiting with error %i\n", testname, error);
	exit(error);
}

int
ssl_timeoutread(SSL *s __attribute__ ((unused)), time_t a __attribute__ ((unused)), char *b  __attribute__ ((unused)),
		const int c  __attribute__ ((unused)), const int f __attribute__ ((unused)))
{
	abort();
}

int
ssl_timeoutwrite(SSL *s __attribute__ ((unused)), time_t a __attribute__ ((unused)), const char *b, const int c)
{
	return write(socketd, b, c);
}

static int allow_ssl_pending = -1;

int
SSL_pending(const SSL *s __attribute__ ((unused)))
{
	if (allow_ssl_pending < 0) {
		fprintf(stderr, "invalid call to SSL_pending()\n");
		dieerror(EFAULT);
	} else {
		return allow_ssl_pending;
	}
}

static int
unexpected_pending(void)
{
	if (data_pending(NULL)) {
		fprintf(stderr, "%s: data pending at start of test\n", testname);
		return 1;
	} else {
		return 0;
	}
}

static void
send_test_data(const char *buf, const size_t len)
{
	/* write data through the pipe, this should cause input data to be available */
	if (netnwrite(buf, len) != 0) {
		fprintf(stderr, "%s: writing test data failed\n", testname);
		exit(1);
	}
}

static int
read_check(const char *data)
{
	int r = net_read(0);
	if (r != 0) {
		fprintf(stderr, "%s: reading good data did not succeed, return value %i error %i\n", testname, r, errno);
		return 1;
	} else if ((linein.len != strlen(data)) || (strcmp(linein.s, data) != 0)) {
		fprintf(stderr, "%s: reading valid data did not return the correct data\nexpected:\t%s\ngot:      \t\n%s\n", testname, data, linein.s);
		return 1;
	}
	return 0;
}

static int
read_check_error(const int errcode)
{
	if (net_read(0) != -1) {
		fprintf(stderr, "%s: reading damaged data did not fail\n", testname);
		return 1;
	} else if (errno != errcode) {
		fprintf(stderr, "%s: reading damaged data did not return %i, but %i\n",
				testname, errcode, errno);
		return 1;
	}
	return 0;
}

static void
send_all_test_data(const char *buf)
{
	/* write data through the pipe, this should cause input data to be available */
	if (netwrite(buf) != 0) {
		fprintf(stderr, "%s: writing test data failed\n", testname);
		exit(1);
	}
}

static int
readline_check(const char *expect, int error)
{
	char buffer[64];
	const size_t len = (expect == NULL) ? 0 : strlen(expect);
	const size_t rexp = (expect == NULL) ? (size_t) -1 : len;

	assert(len <= sizeof(buffer));
	memset(buffer, '#', sizeof(buffer));
	size_t r;
	/* read in as much data as possible to allow buffer testing */
	if ((expect == NULL) || ((len > 2) && (expect[len - 2] == '\r') && (expect[len - 1] == '\n')))
		r = net_readline(sizeof(buffer), buffer);
	else
		r = net_readline(len, buffer);
	if (r != rexp) {
		fprintf(stderr, "%s: net_readline() returned %lu, but expected was %lu\n",
				testname, (unsigned long) r, (unsigned long) rexp);
		return 1;
	} else if ((r == (size_t)-1) && (error != errno)) {
		fprintf(stderr, "%s: net_readline() returned error %i, but expected was %i\n",
				testname, errno, error);
		return 1;
	} else if (r == (size_t)-1) {
		return 0;
	} else if (r != strlen(expect)) {
		fprintf(stderr, "%s: net_readline() returned unexpected length %lu\n",
				testname, (unsigned long) r);
		return 1;
	} else if (strncmp(buffer, expect, rexp) != 0) {
		fprintf(stderr, "%s: net_readline() returned unexpected data\n", testname);
		return 1;
	}
	return 0;
}

static int
test_pending()
{
	int ret = 0;
	const char dummydata[] = "foo\r\nbar\r\n";
	testname = "pending";

	/* nothing happened yet, so no data should be pending */
	for (int i = 0; i < 10; i++)
		if (data_pending(NULL)) {
			fprintf(stderr, "spurious data pending\n");
			ret++;
		}

	send_all_test_data(dummydata);

	if (net_read(0) != 0) {
		fprintf(stderr, "cannot read test data on first try\n");
		return ++ret;
	}

	/* now we have data read, and another line of data should be pending */

	if (!data_pending(NULL)) {
		fprintf(stderr, "no data available on first try\n");
		ret++;
	}

	/* since we did not read in anything here the data should still be available */
	if (!data_pending(NULL)) {
		fprintf(stderr, "no data available on second try\n");
		ret++;
	}

	/* read the data */
	if (net_read(0) != 0) {
		fprintf(stderr, "cannot read test data on second try\n");
		return ++ret;
	}

	if (data_pending(NULL)) {
		fprintf(stderr, "spurious data pending after read\n");
		ret++;
	}

	/* pretend we would be in SSL mode */
	SSL_CTX *ctx = SSL_CTX_new(TLS_method());
	SSL *myssl = SSL_new(ctx);
	SSL_CTX_free(ctx);
	allow_ssl_pending = 0;
	if (data_pending(myssl)) {
		fprintf(stderr, "spurious SSL data pending\n");
		ret++;
	}
	allow_ssl_pending = 1;
	if (!data_pending(myssl)) {
		fprintf(stderr, "SSL pseudo data missing\n");
		ret++;
	}
	SSL_free(myssl);
	allow_ssl_pending = -1;
	if (data_pending(NULL)) {
		fprintf(stderr, "spurious data pending after SSL\n");
		ret++;
	}

	return ret;
}

static int
test_bare_lf_start()
{
	int ret = 0;
	const char dummydata[] = "foo\nbar\r\n";

	testname = "bare LF start";

	if (unexpected_pending())
		return 1;

	/* detection of bare LF in direct input */
	send_all_test_data(dummydata);

	if (read_check_error(EINVAL))
		ret++;

	if (read_check("bar"))
		ret++;

	return ret;
}

static int
test_bare_lf_mid()
{
	int ret = 0;
	const char dummydata[] = "good\r\nfoo\nbar\r\n";

	testname = "bare LF mid";

	/* check detection of bare LF in input buffer */
	send_all_test_data(dummydata);

	if (read_check("good"))
		ret++;

	if (read_check_error(EINVAL))
		ret++;

	if (read_check("bar"))
		ret++;

	/* check again, but this time without the final CRLF present in the input buffer
	 * when detecting the broken line */
	send_test_data(dummydata, strlen(dummydata) - 2);

	if (read_check("good"))
		ret++;

	if (read_check_error(EINVAL))
		ret++;

	send_all_test_data("\r\n");
	if (read_check("bar"))
		ret++;

	/* check again, but this time with the final LF missing in the input buffer, so
	 * we have a bare LF and and a CR at the end of the buffer */
	send_test_data(dummydata, strlen(dummydata) - 1);

	if (read_check("good"))
		ret++;

	if (read_check_error(EINVAL))
		ret++;

	send_all_test_data("\n");
	if (read_check("bar"))
		ret++;

	return ret;
}

static int
test_bare_cr()
{
	int ret = 0;
	const char dummydata[] = "foo\rbar\r\n";

	testname = "bare CR";

	if (unexpected_pending())
		return 1;

	/* detection of bare LF in direct input */
	send_all_test_data(dummydata);

	if (read_check_error(EINVAL))
		ret++;

	if (read_check("bar"))
		ret++;

	return ret;
}

static int
test_bare_cr_lf()
{
	int ret = 0;
	const char dummydata[] = "foo\rfoo\nbar\r\n";

	testname = "bare CR+LF";

	if (unexpected_pending())
		return 1;

	/* detection of bare LF in direct input */
	send_all_test_data(dummydata);

	if (read_check_error(EINVAL))
		ret++;

	if (read_check("bar"))
		ret++;

	return ret;
}

static int
test_bare_lf_cr()
{
	int ret = 0;
	const char dummydata[] = "foo\nfoo\rbar\r\n";

	testname = "bare LF+CR";

	if (unexpected_pending())
		return 1;

	/* detection of bare LF in direct input */
	send_all_test_data(dummydata);

	if (read_check_error(EINVAL))
		ret++;

	if (read_check("bar"))
		ret++;

	return ret;
}

static int
test_cont(void)
{
	int ret = 0;
	const char dummydata[] = "first\r\nsecond\r\nthird\r\n4th\r\n";
	const char *secondcr = strchr(strchr(dummydata, '\r') + 1, '\r');

	testname = "continuation test";

	if (unexpected_pending())
		return 1;

	/* send only part of the data */
	send_test_data(dummydata, strchr(dummydata, 'c') - dummydata);

	/* now the first line is read, and the beginning of the second line is in the buffer */
	if (read_check("first"))
		ret++;

	/* send the rest */
	send_all_test_data(strchr(dummydata, 'c'));

	if (read_check("second"))
		ret++;

	if (read_check("third"))
		ret++;

	if (read_check("4th"))
		ret++;

	/* send the first line and the second one up to the second CR */
	send_test_data(dummydata, secondcr - dummydata);
	if (read_check("first"))
		ret++;

	/* now send the rest of the data, should be a continuation and valid result */
	send_all_test_data(secondcr);

	if (read_check("second"))
		ret++;

	if (read_check("third"))
		ret++;

	if (read_check("4th"))
		ret++;

	return ret;
}

static int
test_long_lines(void)
{
	int ret = 0;
	int i;
	const char valid[] = "\r\nvalid\r\n";

	testname = "long lines";

	if (unexpected_pending())
		return 1;

	/* a line that is clearly too long */
	for (i = 0; i <= 100; i++)
		send_all_test_data(digits);
	send_all_test_data(valid);

	i = data_pending(NULL);
	if (i != 1) {
		fprintf(stderr, "data_pending(NULL) with available data returned %i instead of 1\n", i);
		ret++;
	}

	if (read_check_error(E2BIG))
		ret++;

	if (read_check("valid"))
		ret++;

	/* a line that is too long and that has it's CRLF
	 * wrapped at the buffer boundary */
	for (i = 0; i < 100; i++)
		send_all_test_data(digits);
	send_all_test_data(valid);

	if (read_check_error(E2BIG))
		ret++;

	if (read_check("valid"))
		ret++;

	/* a line that is too long and that has it's CRLF
	 * wrapped at the buffer boundary when inside loop_long() */
	for (i = 0; i < 200; i++)
		send_all_test_data(digits);
	send_all_test_data("X");
	send_all_test_data(valid);

	if (read_check_error(E2BIG))
		ret++;

	if (read_check("valid"))
		ret++;

	/* a line that is too long and then doesn't end in
	 * CRLF, so it becomes even longer */
	for (i = 0; i < 100; i++)
		send_all_test_data(digits);
	send_all_test_data("\r");
	for (i = 0; i < 10; i++)
		send_all_test_data(digits);
	send_all_test_data(valid);

	if (read_check_error(E2BIG))
		ret++;

	if (read_check("valid"))
		ret++;

	/* a line that is too long and then does end in CRCRLF */
	for (i = 0; i < 100; i++)
		send_all_test_data(digits);
	send_all_test_data("\r");
	send_all_test_data(valid);

	if (read_check_error(E2BIG))
		ret++;

	if (read_check("valid"))
		ret++;

	/* a line that is too long and ands in LF. Since no more data is
	 * available in the buffer at that time it should be taken as
	 * line end. */
	for (i = 0; i <= 100; i++)
		send_all_test_data(digits);
	send_all_test_data("\n");

	if (read_check_error(E2BIG))
		ret++;

	send_all_test_data(valid);

	if (read_check(""))
		ret++;
	if (read_check("valid"))
		ret++;

	return ret;
}

static int
test_binary(void)
{
	int ret = 0;
	char outbuf[64];
	const char longbindata[] = "01binary\r\n";
	const char *bindata = longbindata + 2;

	testname = "binary";

	if (unexpected_pending())
		return ++ret;

	/* directly readind binary data */
	send_all_test_data(bindata);

	size_t num = net_readbin(strlen(bindata), outbuf);
	if (num == (size_t)-1) {
		fprintf(stderr, "%s: reading binary data failed, error %i\n", testname, errno);
		ret++;
	} else if (num != strlen(bindata)) {
		fprintf(stderr, "%s: reading binary data did not return %lu byte, but %lu\n",
				testname, (unsigned long) strlen(bindata), (unsigned long) num);
		ret++;
	} else if (strncmp(outbuf, bindata, strlen(bindata)) != 0) {
		fprintf(stderr, "%s: binary data read does not match expected data\n", testname);
		ret++;
	}

	/* writing normal data first, keeping something of that in buffer
	 * to be prepended to binary test data */
	send_all_test_data("first\r\n01");

	if (read_check("first"))
		ret++;

	send_all_test_data(bindata);

	num = net_readbin(strlen(longbindata), outbuf);
	if (num == (size_t)-1) {
		fprintf(stderr, "%s: reading binary data failed, error %i\n", testname, errno);
		ret++;
	} else if (num != strlen(longbindata)) {
		fprintf(stderr, "%s: reading binary data did not return %lu byte, but %lu\n",
				testname, (unsigned long) strlen(longbindata), (unsigned long) num);
		ret++;
	} else if (strncmp(outbuf, longbindata, strlen(longbindata)) != 0) {
		fprintf(stderr, "%s: binary data read does not match expected data\n", testname);
		ret++;
	}

	/* writing normal data first, keeping something of that in buffer
	 * to be prepended to binary test data, but having more in the buffer
	 * than it is read binary */
	send_all_test_data("first\r\n01");
	send_all_test_data(bindata);
	send_all_test_data("third\r\n");

	if (read_check("first"))
		ret++;

	num = net_readbin(strlen(longbindata), outbuf);
	if (num == (size_t)-1) {
		fprintf(stderr, "%s: reading binary data failed, error %i\n", testname, errno);
		ret++;
	} else if (num != strlen(longbindata)) {
		fprintf(stderr, "%s: reading binary data did not return %lu byte, but %lu\n",
				testname, (unsigned long) strlen(longbindata), (unsigned long) num);
		ret++;
	} else if (strncmp(outbuf, longbindata, strlen(longbindata)) != 0) {
		fprintf(stderr, "%s: binary data read does not match expected data\n", testname);
		ret++;
	}

	if (read_check("third"))
		ret++;

	return ret;
}

static int
test_readline(void)
{
	int ret = 0;
	const char okpattern[] = "ok\r\n";
	const char straypattern[] = "stray cr\rstray lf\nproper\r\n";

	testname = "readline simple";

	if (unexpected_pending())
		return ++ret;

	/* send data once, read it back */
	send_all_test_data(okpattern);

	if (readline_check("ok\r\n", 0))
		ret++;

	testname = "readline many";

	if (unexpected_pending())
		return ++ret;

	/* send data 3 times, read it back in parts*/
	send_all_test_data(okpattern);
	send_all_test_data(okpattern);
	send_all_test_data(okpattern);

	if (readline_check("ok\r\n", 0))
		ret++;
	if (readline_check("ok\r", 0))
		ret++;
	if (readline_check("\n", 0))
		ret++;
	if (readline_check("ok\r\n", 0))
		ret++;

	testname = "readline partial end";

	if (unexpected_pending())
		return ++ret;

	/* send partial data with CR at end */
	send_all_test_data(okpattern);
	send_test_data(okpattern, strlen(okpattern) - 1);

	if (readline_check("ok\r\n", 0))
		ret++;
	if (readline_check("ok\r", 0))
		ret++;

	testname = "readline stray";

	if (unexpected_pending())
		return ++ret;

	/* data with error */
	send_all_test_data(straypattern);

	if (readline_check(NULL, EINVAL))
		ret++;
	if (readline_check("proper\r\n", 0))
		ret++;

	testname = "readline long";

	if (unexpected_pending())
		return ++ret;

	/* longer data chunks */
	for (int i = 0; i < 5; i++)
		send_all_test_data(digits);

	if (readline_check("0123", 0))
		ret++;
	if (readline_check("456789", 0))
		ret++;
	for (int i = 0; i < 4; i++)
		if (readline_check(digits, 0))
			ret++;

	testname = "readline CRLF wrap";
	if (unexpected_pending())
		return ++ret;

	/* get a CRLF wrap between buffer and next read */
	send_all_test_data(okpattern);
	send_test_data(okpattern, strlen(okpattern) - 1);

	if (read_check("ok"))
		ret++;

	send_all_test_data("\n");

	if (readline_check("ok\r\n", 0))
		ret++;

	testname = "readline cont";
	if (unexpected_pending())
		return ++ret;

	/* get a line wrap between buffer and next read */
	send_all_test_data(okpattern);
	send_test_data(okpattern, strlen(okpattern) - 2);

	if (read_check("ok"))
		ret++;

	send_all_test_data("\r\n");

	if (readline_check("ok\r\n", 0))
		ret++;

	testname = "readline invalid buffer";
	if (unexpected_pending())
		return ++ret;
	/* put some invalid CRLF sequences in the buffer */
	send_all_test_data(okpattern);
	send_all_test_data(straypattern);

	if (read_check("ok"))
		ret++;
	if (readline_check(NULL, EINVAL))
		ret++;
	if (read_check("proper"))
		ret++;

	testname = "readline stray CR cont";
	if (unexpected_pending())
		return ++ret;
	/* put a stray CR in the buffer, then valid data behind it */
	send_all_test_data(okpattern);
	send_test_data(okpattern, strlen(okpattern) - 1);

	if (read_check("ok"))
		ret++;
	send_all_test_data(okpattern);
	if (readline_check(NULL, EINVAL))
		ret++;
	if (readline_check("ok\r\n", 0))
		ret++;

	return ret;
}

static int
test_net_writen(void)
{
	int ret = 0;
	const char *simple[] = { "250 first", "second", "third", NULL};
	const char *pattern = "abcdefghijklmnopqrstuvwxyz";
	const char *longthings[] = { "250 012345678901234567890123456789", NULL, pattern, NULL };
#define MANY_THINGS 60
	const char *many[MANY_THINGS] = { "250 ", digits };
	char exp[220 + MANY_THINGS * 10];
	char toolongpart[26 * 30 + 1];
	const char *toolong[] = { "250 short enough", toolongpart, NULL };
	char toolongresult[510] = "250-";

	testname = "net_writen";

	if (unexpected_pending())
		return ++ret;

	/* a simple concat */
	if (net_writen(simple) != 0) {
		fprintf(stderr, "%s: cannot write 'simple' output\n", testname);
		return ++ret;
	}

	if (read_check("250 firstsecondthird"))
		ret++;
	if (data_pending(NULL)) {
		fprintf(stderr, "%s: spurious data after 'simple' test\n", testname);
		ret++;
	}

	/* many small messages */
	for (int i = 2; i < MANY_THINGS - 1; i++)
		many[i] = many[1];
	many[MANY_THINGS - 1] = NULL;

	if (net_writen(many) != 0) {
		fprintf(stderr, "%s: cannot write 'many' output\n", testname);
		return ++ret;
	}

	strcpy(exp, many[0]);
	exp[3] = '-';
	for (int i = 1; i < MANY_THINGS - 9; i++)
		strcat(exp, digits);

	if (read_check(exp))
		ret++;

	strcpy(exp, many[0]);
	for (int i = MANY_THINGS - 9; i < MANY_THINGS - 1; i++)
		strcat(exp, digits);

	if (read_check(exp))
		ret++;
	if (data_pending(NULL)) {
		fprintf(stderr, "%s: spurious data after 'many' test\n", testname);
		ret++;
	}

	/* only 3 messages, but the second one is too long to be used
	 * together with any of the other 2 */
	exp[0] = '\0';
	for (int i = 0; i < MANY_THINGS - 10; i++)
		strcat(exp, digits);
	longthings[1] = exp;
	if (net_writen(longthings) != 0) {
		fprintf(stderr, "%s: cannot write 'long' output\n", testname);
		return ++ret;
	}
	if (read_check("250-012345678901234567890123456789"))
		ret++;
	memmove(exp + 4, exp, strlen(exp) + 1);
	memcpy(exp, "250-", 4);
	if (read_check(exp))
		ret++;
	if (read_check("250 abcdefghijklmnopqrstuvwxyz"))
		ret++;

	char *pos = toolongpart;

	while (toolongpart + sizeof(toolongpart) > pos + strlen(pattern)) {
		memcpy(pos, pattern, strlen(pattern));
		pos += strlen(pattern);
	}
	strncat(toolongresult, toolongpart, sizeof(toolongresult) - 6);
	*pos = '\0';
	if (net_writen(toolong) != 0) {
		fprintf(stderr, "%s: cannot write 'too long' output\n", testname);
		return ++ret;
	}
	if (read_check("250-short enough"))
		ret++;
	if (read_check(toolongresult))
		ret++;
	toolongresult[3] = ' ';
	strcpy(toolongresult + 4, toolongpart + sizeof(toolongresult) - 6);
	if (read_check(toolongresult))
		ret++;

	return ret;
}
#undef MANY_THINGS

static int
test_net_write_multiline(void)
{
	int ret = 0;
	const char *simple[] = { "250 first", "second", "third", "\r\n", NULL};
	const char *longthings[] = { "250 012345678901234567890123456789", NULL, "abcdefghijklmnopqrstuvwxyz", "\r\n", NULL };
#define MANY_THINGS 30
	const char *many[MANY_THINGS] = { "250 ", digits };
	char exp[220 + MANY_THINGS * 10];

	testname = "net_write_multiline";

	if (unexpected_pending())
		return ++ret;

	/* a simple concat */
	if (net_write_multiline(simple) != 0) {
		fprintf(stderr, "%s: cannot write 'simple' output\n", testname);
		return ++ret;
	}

	if (read_check("250 firstsecondthird"))
		ret++;
	if (data_pending(NULL)) {
		fprintf(stderr, "%s: spurious data after 'simple' test\n", testname);
		ret++;
	}

	/* many small messages */
	for (int i = 2; i < MANY_THINGS - 2; i++)
		many[i] = digits;
	many[MANY_THINGS - 2] = "\r\n";
	many[MANY_THINGS - 1] = NULL;

	if (net_write_multiline(many) != 0) {
		fprintf(stderr, "%s: cannot write 'many' output\n", testname);
		return ++ret;
	}

	assert(strlen(many[0]) + (MANY_THINGS - 3) * strlen(digits) < sizeof(exp));
	strncpy(exp, many[0], sizeof(exp));
	for (int i = 0; i < MANY_THINGS - 3; i++)
		memcpy(exp + strlen(many[0]) + strlen(digits) * i, digits, strlen(digits));
	exp[strlen(many[0]) + strlen(digits) * MANY_THINGS] = '\0';

	if (read_check(exp))
		ret++;

	if (data_pending(NULL)) {
		fprintf(stderr, "%s: spurious data after 'many' test\n", testname);
		ret++;
	}

	for (int i = 0; i < MANY_THINGS; i++)
		memcpy(exp + strlen(digits) * i, digits, strlen(digits));
	size_t offs = strlen(digits) * MANY_THINGS;
	exp[offs] = '\0';

	longthings[1] = exp;
	if (net_write_multiline(longthings) != 0) {
		fprintf(stderr, "%s: cannot write 'long' output\n", testname);
		return ++ret;
	}
	memmove(exp + strlen(longthings[0]), exp, offs + 1);
	memcpy(exp, longthings[0], strlen(longthings[0]));
	offs += strlen(longthings[0]);
	assert(offs < sizeof(exp) - strlen(longthings[2]) - 1);
	strncpy(exp + offs, longthings[2], strlen(longthings[2]) + 1);
	if (read_check(exp))
		ret++;

	return ret;
}
#undef MANY_THINGS

/**
 * @brief create a socketpair between 0 and the return value
 * @return a socket descriptor
 * @retval <0 creating the socketpair failed
 *
 * This will return one descriptor of a socketpair, the other half is always
 * at fd 0.
 */
static int
setup_socketpair(void)
{
	int sfd[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sfd) != 0) {
		fprintf(stderr, "cannot create socket pair: %i\n", errno);
		return -1;
	}

	if ((sfd[0] != 0) && (sfd[1] != 0)) {
		if (dup2(sfd[0], 0) != 0) {
			fprintf(stderr, "cannot move socket to fd 0: %i\n", errno);
			close(sfd[0]);
			close(sfd[1]);
			return -1;
		}
		return sfd[1];
	} else if (sfd[0] == 0) {
		return sfd[1];
	} else {
		return sfd[0];
	}
}

/**
 * @brief test using a sopcketpair that data_pending(NULL) detects a socket closed by the remote end
 */
static int
test_pending_socketpair_closed(void)
{
	int ret = 0;

	int i = setup_socketpair();
	if (i < 0)
		return ++ret;

	close(i);

	i = data_pending(NULL);
	if (i != -ECONNRESET) {
		fprintf(stderr, "data_pending(NULL) on closed socket returned %i instead of %i (-ECONNRESET)\n", i, -ECONNRESET);
		ret++;
	}

	close(0);

	return ret;
}

/**
 * @brief test using a sopcketpair that net_read() detects a socket closed by the remote end
 */
static int
test_netread_socketpair_closed(void)
{
	int ret = 0;

	int i = setup_socketpair();
	if (i < 0)
		return ++ret;

	close(i);

	i = net_read(0);
	if ((i != -1) || (errno != ECONNRESET)) {
		fprintf(stderr, "net_read() on closed socket returned %i/%i instead of -1/%i (ECONNRESET)\n", i, errno, ECONNRESET);
		ret++;
	}

	close(0);

	return ret;
}

/**
 * @brief test using a sopcketpair that net_read() detects a socket closed by the remote end
 */
static int
test_netread_socketpair_timeout(void)
{
	int ret = 0;

	int j = setup_socketpair();
	if (j < 0)
		return ++ret;

	timeout = 1;
	time_t t1 = time(NULL);
	int i = net_read(0);
	time_t  t2 = time(NULL);
	if ((i != -1) || (errno != ETIMEDOUT)) {
		fprintf(stderr, "net_read() on timeout returned %i/%i instead of -1/%i (ETIMEDOUT)\n", i, errno, ETIMEDOUT);
		ret++;
	}

	if ((t2 - t1 > 2) || (t2 - t1 < 0)) {
		fprintf(stderr, "net_read() for timeout 1 took %li seconds\n", (long)(t2 - t1));
		ret++;
	}

	close(j);
	close(0);

	return ret;
}

/**
 * @brief test reading network data sent in arbitrary chunks
 */
static int
test_chunks(char *exe)
{
	int pipefd[2];
	int ret = 0;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipefd) != 0) {
		fprintf(stderr, "%s: cannot create socket pair\n", __func__);
		return 1;
	}

	if (fcntl(pipefd[0], FD_CLOEXEC) == -1) {
		int err = errno;
		(void) close(pipefd[0]);
		(void) close(pipefd[1]);
		errno = err;
		return -1;
	}

	const pid_t child = fork();

	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		fprintf(stderr, "%s: cannot fork()\n", __func__);
		return 1;
	}

	if (child == 0) {
		char *args[] = { exe, NULL };

		if (pipefd[1] != 1) {
			if (dup2(pipefd[1], 1) != 1) {
				close(pipefd[1]);
				fprintf(stderr, "%s: cannot move write pipe to fd 1\n", __func__);
				exit(1);
			}
			close(pipefd[1]);
		}

		execve(args[0], args, NULL);
		abort();
	}

	close(pipefd[1]);

	if (pipefd[0] != 0) {
		if (dup2(pipefd[0], 0) != 0) {
			close(pipefd[0]);
			kill(child, SIGTERM);
			fprintf(stderr, "%s: cannot move read pipe to fd 0\n", __func__);
			return 1;
		}
	}

	timeout = 2;
	for (unsigned int i = 0; read_chunks[i] != NULL; ) {
		int k = net_read(0);

		if (k != 0) {
			fprintf(stderr, "%s: read %u returned %i\n", __func__, i, k);
			ret++;
			i++;
			continue;
		}

		if (strcmp(linein.s, read_chunks[i]) != 0) {
			fprintf(stderr, "%s: read '%s' but expected chunk %u: '%s'\n",
				__func__, linein.s, i, read_chunks[i]);
			ret++;
		}
		i++;
	}

	int stat;
	if (waitpid(child, &stat, 0) != child) {
		fprintf(stderr, "%s: waiting for child failed\n", __func__);
		return ++ret;
	}

	if (!WIFEXITED(stat) || (WEXITSTATUS(stat) != 0)) {
		fprintf(stderr, "%s: child failed: exited %i status %i\n",
			__func__, WIFEXITED(stat), WEXITSTATUS(stat));
		return ++ret;
	}

	return ret;
}

int
main(int argc, char **argv)
{
	int ret = 0;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s /path/to/client\n", argv[0]);
		return 1;
	}

	/* Replace stdin. We don't really read from it, but we need to provide
	 * a virtual input pipe for later reads. */
	int pipefd[2];
	if (pipe(pipefd) != 0) {
		fprintf(stderr, "%s: cannot create pipe pair\n", __func__);
		return 1;
	}

	if (dup2(pipefd[0], 0) != 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		fprintf(stderr, "%s: cannot move read pipe to fd 0\n", __func__);
		return 1;
	}

	close(pipefd[0]);
	socketd = pipefd[1];

	/* test any combination of tests */
	for (int i = 1; i < 0x400; i++) {
		if (i & 1)
			ret += test_pending();
		if (i & 2)
			ret += test_bare_lf_start();
		if (i & 4)
			ret += test_bare_lf_mid();
		if (i & 8)
			ret += test_bare_cr();
		if (i & 0x10)
			ret += test_bare_cr_lf();
		if (i & 0x20)
			ret += test_bare_lf_cr();
		if (i & 0x40)
			ret += test_cont();
		if (i & 0x80)
			ret += test_long_lines();
		if (i & 0x100)
			ret += test_binary();
		if (i & 0x200)
			ret += test_readline();
	}

	ret += test_net_writen();
	ret += test_net_write_multiline();

	int i = data_pending(NULL);
	if (i != 0) {
		fprintf(stderr, "data pending at end of tests: %i\n", i);
		ret++;
	}

	close(0);
	close(socketd);

	i = data_pending(NULL);
	if (i != -EBADF) {
		fprintf(stderr, "data_pending(NULL) on closed fd returned %i instead of %i (-EBADF)\n", i, -EBADF);
		ret++;
	}

	ret += test_pending_socketpair_closed();
	ret += test_netread_socketpair_closed();
	ret += test_netread_socketpair_timeout();
	ret += test_chunks(argv[1]);

	CONF_modules_unload(1);
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
#ifndef LIBRESSL_VERSION_NUMBER
	SSL_COMP_free_compression_methods();
#endif

	return ret;
}
