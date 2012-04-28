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

static int
test_pending()
{
	int ret = 0;
	int i;
	const char dummydata[] = "foo\r\nbar\r\n";
	SSL dummyssl;

	/* nothing happened yet, so no data should be pending */
	for (i = 0; i < 10; i++)
		if (data_pending()) {
			fprintf(stderr, "spurious data pending\n");
			ret++;
		}

	/* write data through the pipe, this should cause input data to be available */
	if (netwrite(dummydata) != 0) {
		fprintf(stderr, "writing test data failed\n");
		return ++ret;
	}

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
test_bare_lf()
{
	int ret = 0;
	const char dummydata[] = "good\r\nfoo\nbar\r\n";

	if (data_pending()) {
		fprintf(stderr, "data pending at start of bare LF test\n");
		return 1;
	}

	/* check detection of bare LF in input buffer */
	if (netwrite(dummydata) != 0) {
		fprintf(stderr, "writing test data failed\n");
		return ++ret;
	}

	if (net_read() != 0) {
		fprintf(stderr, "reading good data did not succeed\n");
		ret++;
	} else if ((linelen != 4) || (strcmp(linein, "good") != 0)) {
		fprintf(stderr, "reading valid data did not return the correct data\n");
		ret++;
	}

	if (net_read() != -1) {
		fprintf(stderr, "reading damaged data did not fail\n");
		ret++;
	} else if (errno != EINVAL) {
		fprintf(stderr, "reading damaged data did not return EINVAL, but %i\n", errno);
		ret++;
	}

	if (net_read() != 0) {
		fprintf(stderr, "reading after bare LF did not succeed\n");
		ret++;
	} else if ((linelen != 3) || (strcmp(linein, "bar") != 0)) {
		fprintf(stderr, "reading valid data after bare LF did not return the correct data\n");
		ret++;
	}

	return ret;
}

int main(void)
{
	int ret = 0;
	int pipefd[2];

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

	ret += test_pending();
	ret += test_bare_lf();

	return ret;
}
