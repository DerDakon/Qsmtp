/** \file auth_errors_test.c
 * \brief Authentication error testcases
 *
 * This does not test syntactically correct authentication with an invalid
 * password, but syntax errors and other error cases.
 */

#include "base64.h"
#include <qsmtpd/qsauth.h>
#include <qsmtpd/qsmtpd.h>
#include "sstring.h"

#include "test_io/testcase_io.h"

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <openssl/ssl.h>

struct xmitstat xmitstat;
SSL *ssl = NULL;
unsigned long sslauth = 0;
char linein[1002];
size_t linelen;

const char *expected_net_write1, *expected_net_write2;

static int err;

static int test_netnwrite(const char *s, const size_t len __attribute__((unused)))
{
	if (expected_net_write1 == NULL) {
		fprintf(stderr, "no message expected, but received '%s'\n", s);
		err++;
		errno = EINVAL;
		return -1;
	}

	if (strcmp(s, expected_net_write1) != 0) {
		fprintf(stderr, "expected message '%s', but received '%s'\n", expected_net_write1, s);
		err++;
		errno = EINVAL;
		return -1;
	}

	expected_net_write1 = expected_net_write2;
	expected_net_write2 = NULL;
	return 0;
}

static const char *extra_read;

static size_t
test_net_readline(size_t num, char *buf)
{
	size_t len = strlen(extra_read);

	strncpy(buf, extra_read, num);

	return len < num ? len : num;
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

	if (expected_net_write1 != NULL) {
		fprintf(stderr, "expected message '%s' was not received\n",
				expected_net_write1);
		err++;
	}

	if (expected_net_write2 != NULL) {
		fprintf(stderr, "expected message '%s' was not received\n",
				expected_net_write2);
		err++;
	}
}

int
main(int argc __attribute__((unused)), char **argv)
{
	const char *invalid_msg = "501 5.5.4 malformed auth input\r\n";
	const char *cancel_msg = "501 5.0.0 auth exchange cancelled\r\n";
	const char *argv_auth[] = { argv[0], "foo.example.com", "/bin/false", "" };

	testcase_setup_netnwrite(test_netnwrite);
	testcase_setup_net_readline(test_net_readline);
	testcase_setup_log_write(test_log_write);

	auth_setup(4, argv_auth);

	/* invalid AUTH mechanism */
	strcpy(linein, "AUTH BOGUS");
	linelen = strlen(linein);

	expected_net_write1 = "504 5.5.1 Unrecognized authentication type.\r\n";

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "unrecognized AUTH mechanism was not rejected\n");
		err++;
	}

	check_all_msgs();

	/* invalid base64 message */
	strcpy(linein, "AUTH PLAIN #");
	linelen = strlen(linein);

	expected_net_write1 = invalid_msg;

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH PLAIN with invalid base64 did not fail as expected\n");
		err++;
	}

	check_all_msgs();

	/* auth aborted */
	extra_read = "*\r\n";
	strcpy(linein, "AUTH PLAIN");
	linelen = strlen(linein);

	expected_net_write1 = "334 \r\n";
	expected_net_write2 = cancel_msg;

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "cancelling AUTH PLAIN did not fail as expected\n");
		err++;
	}

	check_all_msgs();

	/* empty line as AUTH data */
	extra_read = "\r\n";
	strcpy(linein, "AUTH PLAIN");
	linelen = strlen(linein);

	expected_net_write1 = "334 \r\n";
	expected_net_write2 = invalid_msg;
	
	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH PLAIN with empty line did not fail as expected\n");
		err++;
	}

	check_all_msgs();

	/* invalid base64 as AUTH data */
	extra_read = "#\r\n";
	strcpy(linein, "AUTH PLAIN");
	linelen = strlen(linein);

	expected_net_write1 = "334 \r\n";
	expected_net_write2 = invalid_msg;

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH PLAIN with invalid base64 line did not fail as expected\n");
		err++;
	}

	check_all_msgs();

	/* missing password */
	strcpy(linein, "AUTH PLAIN AGZvbwA=");
	linelen = strlen(linein);

	expected_net_write1 = invalid_msg;

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH PLAIN without password did not fail as expected\n");
		err++;
	}

	check_all_msgs();

	/* invalid base64 message */
	strcpy(linein, "AUTH LOGIN #");
	linelen = strlen(linein);

	expected_net_write1 = invalid_msg;

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH LOGIN with invalid base64 did not fail as expected\n");
		err++;
	}

	check_all_msgs();

	/* invalid base64 message as username */
	strcpy(linein, "AUTH LOGIN");
	linelen = strlen(linein);

	expected_net_write1 = "334 VXNlcm5hbWU6\r\n";
	expected_net_write2 = invalid_msg;
	extra_read = "#\r\n";

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH LOGIN with invalid username base64 line did not fail as expected\n");
		err++;
	}

	check_all_msgs();

	/* invalid base64 message as password */
	strcpy(linein, "AUTH LOGIN YQ==");
	linelen = strlen(linein);

	expected_net_write1 = "334 UGFzc3dvcmQ6\r\n";
	expected_net_write2 = invalid_msg;
	extra_read = "#\r\n";

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH LOGIN with invalid password base64 line did not fail as expected\n");
		err++;
	}

	check_all_msgs();

	/* empty line as username */
	strcpy(linein, "AUTH LOGIN");
	linelen = strlen(linein);

	expected_net_write1 = "334 VXNlcm5hbWU6\r\n";
	expected_net_write2 = invalid_msg;
	extra_read = "\r\n";

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH LOGIN with empty username base64 line did not fail as expected\n");
		err++;
	}

	check_all_msgs();

	/* empty line as password */
	strcpy(linein, "AUTH LOGIN YQ==");
	linelen = strlen(linein);

	expected_net_write1 = "334 UGFzc3dvcmQ6\r\n";
	expected_net_write2 = invalid_msg;
	extra_read = "\r\n";

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH LOGIN with empty password base64 line did not fail as expected\n");
		err++;
	}

	check_all_msgs();

	/* empty line as password */
	strcpy(linein, "AUTH LOGIN YQ==");
	linelen = strlen(linein);

	expected_net_write1 = "334 UGFzc3dvcmQ6\r\n";
	expected_net_write2 = invalid_msg;
	extra_read = "===\r\n";

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH LOGIN with empty password base64 line did not fail as expected\n");
		err++;
	}

	check_all_msgs();

	return err;
}


pid_t fork_clean(void)
{
	return -1;
}

void
tarpit(void)
{
}
