#include "log.h"
#include "netio.h"
#include "tls.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/ssl.h>

#ifdef DEBUG_IO
#include "log.h"
void
log_write(int priority __attribute__ ((unused)), const char *s __attribute__ ((unused)))
{
	dieerror(EFAULT);
}
#endif

SSL *ssl;
int socketd;

void
dieerror(int error)
{
	exit(error);
}

int
ssl_timeoutread(time_t a __attribute__ ((unused)), char *b  __attribute__ ((unused)), const int c  __attribute__ ((unused)))
{
	dieerror(EFAULT);
}

int
ssl_timeoutwrite(time_t a __attribute__ ((unused)), const char *b, const int c)
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

static const char *testname;

static int
unexpected_pending(void)
{
	if (data_pending()) {
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
	if (net_read() != 0) {
		fprintf(stderr, "%s: reading good data did not succeed\n", testname);
		return 1;
	} else if ((linelen != strlen(data)) || (strcmp(linein, data) != 0)) {
		fprintf(stderr, "%s: reading valid data did not return the correct data (%s)\n", testname, data);
		return 1;
	}
	return 0;
}

static inline void
send_all_test_data(const char *buf)
{
	send_test_data(buf, strlen(buf));
}

static int
test_pending()
{
	int ret = 0;
	int i;
	const char dummydata[] = "foo\r\nbar\r\n";
	SSL dummyssl;
	testname = "pending";

	/* nothing happened yet, so no data should be pending */
	for (i = 0; i < 10; i++)
		if (data_pending()) {
			fprintf(stderr, "spurious data pending\n");
			ret++;
		}

	send_all_test_data(dummydata);

	if (net_read() != 0) {
		fprintf(stderr, "cannot read test data on first try\n");
		return ++ret;
	}

	/* now we have data read, and another line of data should be pending */

	linelen = 1;
	if (!data_pending()) {
		fprintf(stderr, "no data available on first try\n");
		ret++;
	}

	/* since we did not read in anything here the data should still be available */
	if (!data_pending()) {
		fprintf(stderr, "no data available on second try\n");
		ret++;
	}

	/* read the data */
	if (net_read() != 0) {
		fprintf(stderr, "cannot read test data on second try\n");
		return ++ret;
	}

	if (data_pending()) {
		fprintf(stderr, "spurious data pending after read\n");
		ret++;
	}

	/* pretend we would be in SSL mode */
	ssl = &dummyssl;
	allow_ssl_pending = 0;
	if (data_pending()) {
		fprintf(stderr, "spurious SSL data pending\n");
		ret++;
	}
	allow_ssl_pending = 1;
	if (!data_pending()) {
		fprintf(stderr, "SSL pseudo data missing\n");
		ret++;
	}
	ssl = NULL;
	allow_ssl_pending = -1;
	if (data_pending()) {
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

	if (net_read() != -1) {
		fprintf(stderr, "reading damaged data did not fail\n");
		ret++;
	} else if (errno != EINVAL) {
		fprintf(stderr, "reading damaged data did not return EINVAL, but %i\n", errno);
		ret++;
	}

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

	if (net_read() != -1) {
		fprintf(stderr, "reading damaged data did not fail\n");
		ret++;
	} else if (errno != EINVAL) {
		fprintf(stderr, "reading damaged data did not return EINVAL, but %i\n", errno);
		ret++;
	}

	if (read_check("bar"))
		ret++;

	/* check again, but this time without the final CRLF present in the input buffer
	 * when detecting the broken line */
	send_test_data(dummydata, strlen(dummydata) - 2);

	if (read_check("good"))
		ret++;

	if (net_read() != -1) {
		fprintf(stderr, "reading damaged data did not fail\n");
		ret++;
	} else if (errno != EINVAL) {
		fprintf(stderr, "reading damaged data did not return EINVAL, but %i\n", errno);
		ret++;
	}

	send_all_test_data("\r\n");
	if (read_check("bar"))
		ret++;

	/* check again, but this time with the final LF missing in the input buffer, so
	 * we have a bare LF and and a CR at the end of the buffer */
	send_test_data(dummydata, strlen(dummydata) - 1);

	if (read_check("good"))
		ret++;

	if (net_read() != -1) {
		fprintf(stderr, "reading damaged data did not fail\n");
		ret++;
	} else if (errno != EINVAL) {
		fprintf(stderr, "reading damaged data did not return EINVAL, but %i\n", errno);
		ret++;
	}

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

	if (net_read() != -1) {
		fprintf(stderr, "reading damaged data did not fail\n");
		ret++;
	} else if (errno != EINVAL) {
		fprintf(stderr, "reading damaged data did not return EINVAL, but %i\n", errno);
		ret++;
	}

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

	if (net_read() != -1) {
		fprintf(stderr, "reading damaged data did not fail\n");
		ret++;
	} else if (errno != EINVAL) {
		fprintf(stderr, "reading damaged data did not return EINVAL, but %i\n", errno);
		ret++;
	}

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

	if (net_read() != -1) {
		fprintf(stderr, "reading damaged data did not fail\n");
		ret++;
	} else if (errno != EINVAL) {
		fprintf(stderr, "reading damaged data did not return EINVAL, but %i\n", errno);
		ret++;
	}

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
	const char digits[] = "0123456789";
	const char valid[] = "\r\nvalid\r\n";

	testname = "long lines";

	if (unexpected_pending())
		return 1;

	for (i = 0; i <= 100; i++)
		send_all_test_data(digits);
	send_all_test_data(valid);

	if (net_read() != -1) {
		fprintf(stderr, "reading damaged data did not fail\n");
		ret++;
	} else if (errno != E2BIG) {
		fprintf(stderr, "reading damaged data did not return EINVAL, but %i\n", errno);
		ret++;
	}

	if (read_check("valid"))
		ret++;

	return ret;
}

int main(void)
{
	int ret = 0;
	int pipefd[2];
	int i;

	/* Replace stdin. We don't really read from it, but we need to provide
	 * a virtual input pipe for later reads. */
	if (pipe(pipefd) != 0) {
		fprintf(stderr, "cannot create pipe pair\n");
		return 1;
	}

	if (dup2(pipefd[0], 0) != 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		fprintf(stderr, "cannot move read pipe to fd 0\n");
		return 1;
	}

	close(pipefd[0]);
	socketd = pipefd[1];

	/* test any combination of tests */
	for (i = 1; i < 0x100; i++) {
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
	}

	if (data_pending()) {
		fprintf(stderr, "data pending at end of tests\n");
		ret++;
	}

	return ret;
}
