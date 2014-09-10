#include <qremote/qremote.h>

#include "test_io/testcase_io.h"

#include <stdio.h>
#include <syslog.h>

char *rhost = (char *)"remote.example.com";

void
err_mem(int i __attribute__ ((unused)))
{
	abort();
}

void
write_status(const char *str __attribute__ ((unused)))
{
	abort();
}

void
write_status_m(const char **strs __attribute__ ((unused)), const unsigned int count __attribute__ ((unused)))
{
	abort();
}

static unsigned int want_quitmsg;

void
quitmsg(void)
{
	if (!want_quitmsg)
		abort();

	want_quitmsg = 0;
}

static int
verify_test(const int fatal, const int expected_result)
{
	int err = 0;
	int result;

	net_read_fatal = fatal;

	result = netget(fatal);

	if (result != expected_result) {
		fprintf(stderr, "netget() returned %i instead of %i\n",
				result, expected_result);
		err++;
	}

	if (log_write_msg != NULL) {
		fprintf(stderr, "expected log message '%s' was not received\n",
				log_write_msg);
		err++;
		log_write_msg = NULL;
	}

	if (want_quitmsg != 0) {
		fprintf(stderr, "expected call to quitmsg() did not happen\n");
		err++;
		want_quitmsg = 0;
	}

	return err;
}

int
main(void)
{
	int err = 0;
	int i;

	testcase_setup_net_read(testcase_net_read_simple);
	testcase_setup_log_writen(testcase_log_writen_combine);
	testcase_setup_log_write(testcase_log_write_compare);

	net_read_msg = (char *)EINVAL;
	err += verify_test(0, -EINVAL);

	net_read_msg = (char *)E2BIG;
	err += verify_test(0, -EINVAL);

	log_write_msg = "connection to remote.example.com timed out";
	log_write_priority = LOG_ERR;
	net_read_msg = (char *)ETIMEDOUT;
	err += verify_test(0, -ETIMEDOUT);

	log_write_msg = "connection to remote.example.com died";
	log_write_priority = LOG_ERR;
	net_read_msg = (char *)ECONNRESET;
	err += verify_test(0, -ECONNRESET);

	net_read_msg = (char *)EPIPE;
	want_quitmsg = 1;
	err += verify_test(0, -EPIPE);

	/* length must be at least 4 characters */
	net_read_msg = "";
	err += verify_test(0, -EINVAL);

	net_read_msg = "1";
	err += verify_test(0, -EINVAL);

	net_read_msg = "12";
	err += verify_test(0, -EINVAL);

	net_read_msg = "123";
	err += verify_test(0, -EINVAL);

	/* the 4th character must be either a space or hyphen */
	net_read_msg = "2504";
	err += verify_test(0, -EINVAL);

	/* the first 3 characters must be digits, the first one between 2 and 5 */
	net_read_msg = " 12 ";
	err += verify_test(0, -EINVAL);

	net_read_msg = "2 2 ";
	err += verify_test(0, -EINVAL);

	net_read_msg = "22  ";
	err += verify_test(0, -EINVAL);

	net_read_msg = " 12-";
	err += verify_test(0, -EINVAL);

	net_read_msg = "2 2-";
	err += verify_test(0, -EINVAL);

	net_read_msg = "22 -";
	err += verify_test(0, -EINVAL);

	net_read_msg = "120-";
	err += verify_test(0, -EINVAL);

	/* now all correct results */
	for (i = 200; i < 600; i++) {
		char buf[8];

		snprintf(buf, sizeof(buf), "%i ", i);
		net_read_msg = buf;
		err += verify_test(1, i);

		snprintf(buf, sizeof(buf), "%i-", i);
		net_read_msg = buf;
		err += verify_test(1, i);
	}

	/* just to be sure: all other NNN[ -] results again */
	for (i = 0; i < 200; i++) {
		char buf[8];

		snprintf(buf, sizeof(buf), "%3i ", i);
		net_read_msg = buf;
		err += verify_test(0, -EINVAL);

		snprintf(buf, sizeof(buf), "%3i-", i);
		net_read_msg = buf;
		err += verify_test(0, -EINVAL);
	}

	for (i = 600; i < 1000; i++) {
		char buf[8];

		snprintf(buf, sizeof(buf), "%i ", i);
		net_read_msg = buf;
		err += verify_test(0, -EINVAL);

		snprintf(buf, sizeof(buf), "%i-", i);
		net_read_msg = buf;
		err += verify_test(0, -EINVAL);
	}

	return err;
}
