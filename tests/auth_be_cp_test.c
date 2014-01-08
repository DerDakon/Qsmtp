/** \file auth_be_cp_test.c
 * \brief Testcases for checkpassword authentication backend.
 */

#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/qsauth_backend.h>
#include <sstring.h>

#include "test_io/testcase_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

const char *tempnoauth = "[MSG:tempnoauth]";

static int err;	/* global error counter */
static const char *expected_net_write;

static int test_netnwrite(const char *s, const size_t len __attribute__((unused)))
{
	if (expected_net_write == NULL) {
		fprintf(stderr, "no message expected, but received '%s'\n", s);
		err++;
		errno = EINVAL;
		return -1;
	}

	if (strcmp(s, expected_net_write) != 0) {
		fprintf(stderr, "expected message '%s', but received '%s'\n", expected_net_write, s);
		err++;
		errno = EINVAL;
		return -1;
	}

	expected_net_write = NULL;
	return 0;
}

static const char *expected_log;

static void
test_log_write(int priority, const char *s)
{
	if (expected_log == NULL) {
		fprintf(stderr, "no log message expected, but received '%s'\n", s);
		err++;
		return;
	}

	if (strcmp(s, expected_log) != 0) {
		fprintf(stderr, "expected log message '%s', but received '%s'\n", expected_log, s);
		err++;
		return;
	}

	if (priority != LOG_ERR) {
		fprintf(stderr, "log priority LOG_ERR (%i) expected, but got %i\n", LOG_ERR, priority);
		err++;
		return;
	}

	expected_log = NULL;
}

static void
check_all_msgs(void)
{
	if (expected_log != NULL) {
		fprintf(stderr, "expected log message '%s' was not received\n",
				expected_log);
		err++;
	}

	if (expected_net_write != NULL) {
		fprintf(stderr, "expected message '%s' was not received\n",
				expected_net_write);
		err++;
	}
}

static int fork_success;

pid_t fork_clean(void)
{
	if (!fork_success)
		return -1;

	return fork();
}

static void
test_fork_fail(void)
{
	struct string sdummy;

	sdummy.s = "abc";
	sdummy.len = strlen(sdummy.s);

	fork_success = 0;
	expected_log = "cannot fork auth";
	expected_net_write = tempnoauth;

	if (auth_backend_execute(&sdummy, &sdummy, &sdummy) != -EDONE) {
		fprintf(stderr, "auth_backend_execute() did not return -EDONE after failed fork\n");
		err++;
	}

	check_all_msgs();
}

int
main(void)
{
	testcase_setup_log_write(test_log_write);
	testcase_setup_netnwrite(test_netnwrite);

	test_fork_fail();

	return err;
}
