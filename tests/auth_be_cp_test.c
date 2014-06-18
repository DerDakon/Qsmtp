/** \file auth_be_cp_test.c
 * \brief Testcases for checkpassword authentication backend.
 */

#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/qsauth_backend.h>
#include <sstring.h>

#include "auth_users.h"
#include "test_io/testcase_io.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

const char *tempnoauth = "[MSG:tempnoauth]";

static int err;	/* global error counter */

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

static int expect_log_writen;
static char baddummy[PATH_MAX];

void
test_log_writen(int priority, const char **msg)
{
	const char *log_multi_expect[] = { "checkpassword program '", baddummy,
			"' is not executable, error was: ",
			strerror(ENOTDIR), NULL };
	unsigned int c;

	if (!expect_log_writen) {
		int i;

		fprintf(stderr, "unexpected call to %s(), args:\n", __func__);

		for (i = 0; msg[i] != NULL; i++)
			fprintf(stderr, "\t%s\n", msg[i]);
		err++;
		return;
	} else {
		expect_log_writen = 0;
	}

	if (priority != LOG_WARNING) {
		fprintf(stderr, "log_writen(%i, ...) called, but expected priority is LOG_WARNING\n",
				priority);
		err++;
	}

	for (c = 0; msg[c] != NULL; c++) {
		if (log_multi_expect[c] == NULL) {
			fprintf(stderr, "log_writen(%i, ...) called, but expected parameter at position %u is NULL\n",
					priority, c);
			err++;
		}
		if (strcmp(log_multi_expect[c], msg[c]) != 0) {
			fprintf(stderr, "log_writen(%i, ...) called, but parameter at position %u is '%s' instead of '%s'\n",
					priority, c, msg[c], log_multi_expect[c]);
			err++;
		}
	}

	if (log_multi_expect[c] != NULL) {
		fprintf(stderr, "log_writen(%i, ...) called, but expected parameter at position %u is not NULL, but %s\n",
				priority, c, log_multi_expect[c]);
		err++;
	}
}

static void
check_all_msgs(void)
{
	if (expected_log != NULL) {
		fprintf(stderr, "expected log message '%s' was not received\n",
				expected_log);
		err++;
	}

	if (netnwrite_msg != NULL) {
		fprintf(stderr, "expected message '%s' was not received\n",
				netnwrite_msg);
		err++;
	}

	if (expect_log_writen) {
		fprintf(stderr, "expected call to log_writen() was not received\n");
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

/**
 * @brief test when fork fails
 */
static void
test_fork_fail(void)
{
	struct string sdummy;

	sdummy.s = "abc";
	sdummy.len = strlen(sdummy.s);

	fork_success = 0;
	expected_log = "cannot fork auth";
	netnwrite_msg = tempnoauth;

	if (auth_backend_execute(&sdummy, &sdummy, &sdummy) != -EDONE) {
		fprintf(stderr, "auth_backend_execute() did not return -EDONE after failed fork\n");
		err++;
	}

	check_all_msgs();
}

/**
 * @brief test abort in helper
 */
static void
test_chkpw_abort(void)
{
	struct string user = { .s = (char *)users[0].username, .len = strlen(users[0].username) };
	struct string pass = { .s = (char *)users[0].password, .len = strlen(users[0].password) };

	fork_success = 1;
	expected_log = "auth child crashed";
	netnwrite_msg = tempnoauth;

	if (auth_backend_execute(&user, &pass, NULL) != -EDONE) {
		fprintf(stderr, "auth_backend_execute() did not return -EDONE after aborted child\n");
		err++;
	}

	check_all_msgs();
}

/**
 * @brief test wrong password in authentication
 */
static void
test_chkpw_wrong(void)
{
	struct string user = { .s = (char *)users[1].username, .len = strlen(users[1].username) };
	struct string resp;

	STREMPTY(resp);

	fork_success = 1;

	if (auth_backend_execute(&user, &user, &resp) != 1) {
		fprintf(stderr, "auth_backend_execute() did not return 1 for wrong password\n");
		err++;
	}

	check_all_msgs();
}

/**
 * @brief test wrong password in authentication
 */
static void
test_chkpw_correct(void)
{
	struct string user = { .s = (char *)users[1].username, .len = strlen(users[1].username) };
	struct string pass = { .s = (char *)users[1].password, .len = strlen(users[1].password) };

	fork_success = 1;

	if (auth_backend_execute(&user, &pass, NULL) != 0) {
		fprintf(stderr, "auth_backend_execute() did not return 0 for correct password\n");
		err++;
	}

	check_all_msgs();
}

/**
 * @brief test auth_backend_setup() with invalid arguments
 */
static void
test_setup_errors(const char *dummy)
{
	const char *args_invalid_count[] = { "Qsmtpd", "foo.example.com" };
	const char *args_noexec[] = { "Qsmtpd", "foo.example.com", baddummy, "" };

	assert(strlen(dummy) + strlen("/something") < sizeof(baddummy));
	strcpy(baddummy, dummy);
	strcat(baddummy, "/something");

	expected_log = "invalid number of parameters given";
	if (auth_backend_setup(2, args_invalid_count) != -EINVAL) {
		fprintf(stderr, "auth_backend_setup(2, ...) returned wrong error code\n");
		err++;
	}

	expect_log_writen = 1;
	if (auth_backend_setup(4, args_noexec) != -EACCES) {
		fprintf(stderr, "auth_backend_setup(4, ...) returned wrong error code\n");
		err++;
	}

	check_all_msgs();
}

int
main(int argc, char **argv)
{
	const char *args[] = { "Qsmtpd", "foo.example.com", argv[1], autharg };
	if (argc != 2) {
		fprintf(stderr, "Usage: %s auth_dummy\n", argv[0]);
		return 1;
	}

	testcase_setup_log_write(test_log_write);
	testcase_setup_netnwrite(testcase_netnwrite_compare);

	test_fork_fail();

	testcase_setup_log_writen(test_log_writen);

	test_setup_errors(argv[1]);

	if (auth_backend_setup(4, args) != 0) {
		fprintf(stderr, "correct call to auth_backend_setup() failed\n");
		return ++err;
	}

	test_chkpw_abort();
	test_chkpw_wrong();
	test_chkpw_correct();

	return err;
}
