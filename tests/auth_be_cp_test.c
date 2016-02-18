/** \file auth_be_cp_test.c
 * \brief Testcases for checkpassword authentication backend.
 */

#include <qsmtpd/qsauth_backend.h>

#include "auth_users.h"
#include <qsmtpd/qsmtpd.h>
#include <sstring.h>
#include "test_io/testcase_io.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

const char *tempnoauth = "[MSG:tempnoauth]";

static int err;	/* global error counter */

static char baddummy[PATH_MAX];

static void
check_all_msgs(const char *caller)
{
	if (log_write_msg != NULL) {
		fprintf(stderr, "%s: expected log message '%s' was not received\n",
				caller, log_write_msg);
		err++;
	}

	err += testcase_netnwrite_check(caller);
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
	log_write_msg = "cannot fork auth";
	log_write_priority = LOG_ERR;
	netnwrite_msg = tempnoauth;

	if (auth_backend_execute(&sdummy, &sdummy, &sdummy) != -EDONE) {
		fprintf(stderr, "auth_backend_execute() did not return -EDONE after failed fork\n");
		err++;
	}

	check_all_msgs(__func__);
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
	log_write_msg = "auth child crashed";
	log_write_priority = LOG_ERR;
	netnwrite_msg = tempnoauth;

	if (auth_backend_execute(&user, &pass, NULL) != -EDONE) {
		fprintf(stderr, "auth_backend_execute() did not return -EDONE after aborted child\n");
		err++;
	}

	check_all_msgs(__func__);
}

/**
 * @brief test wrong password in authentication
 */
static void
test_chkpw_wrong(void)
{
	struct string user = { .s = (char *)users[1].username, .len = strlen(users[1].username) };
	struct string resp = STREMPTY_INIT;

	fork_success = 1;

	if (auth_backend_execute(&user, &user, &resp) != 1) {
		fprintf(stderr, "auth_backend_execute() did not return 1 for wrong password\n");
		err++;
	}

	check_all_msgs(__func__);
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

	check_all_msgs(__func__);
}

/**
 * @brief test auth_backend_setup() with invalid arguments
 */
static void
test_setup_errors(const char *dummy)
{
	const char *args_invalid_count[] = { "Qsmtpd", "foo.example.com" };
	const char *args_noexec[] = { "Qsmtpd", "foo.example.com", baddummy, "" };
	char logbuf[sizeof(baddummy) + 100];

	assert(strlen(dummy) + strlen("/something") < sizeof(baddummy));
	strcpy(baddummy, dummy);
	strcat(baddummy, "/something");

	snprintf(logbuf, sizeof(logbuf), "checkpassword program '%s' is not executable, error was: %s",
			baddummy, strerror(ENOTDIR));

	log_write_msg = "invalid number of parameters given";
	log_write_priority = LOG_ERR;
	if (auth_backend_setup(2, args_invalid_count) != -EINVAL) {
		fprintf(stderr, "auth_backend_setup(2, ...) returned wrong error code\n");
		err++;
	}

	log_write_msg = logbuf;
	log_write_priority = LOG_WARNING;
	if (auth_backend_setup(4, args_noexec) != -EACCES) {
		fprintf(stderr, "auth_backend_setup(4, ...) returned wrong error code\n");
		err++;
	}

	check_all_msgs(__func__);
}

int
main(int argc, char **argv)
{
	const char *args[] = { "Qsmtpd", "foo.example.com", argv[1], autharg };
	if (argc != 2) {
		fprintf(stderr, "Usage: %s auth_dummy\n", argv[0]);
		return 1;
	}

	testcase_setup_log_write(testcase_log_write_compare);
	testcase_setup_netnwrite(testcase_netnwrite_compare);

	test_fork_fail();

	testcase_setup_log_writen(testcase_log_writen_combine);

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
