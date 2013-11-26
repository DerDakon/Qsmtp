/** \file auth_errors_test.c
 * \brief Authentication error testcases
 *
 * This does not test syntactically correct authentication with an invalid
 * password, but syntax errors and other error cases.
 */

#include "base64.h"
#include "qsauth.h"
#include "qsmtpd.h"
#include "sstring.h"

#include "test_io/testcase_io.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>

#include "auth_users.h"

struct xmitstat xmitstat;
SSL *ssl = NULL;
unsigned long sslauth = 0;
char linein[1002];
size_t linelen;
const char *auth_host;
const char *auth_check;
const char **auth_sub;

const char *expected_net_write1, *expected_net_write2;

static int err;

static int test_netwrite(const char *s)
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

int
main(void)
{
	const char *invalid_msg = "501 5.5.4 malformed auth input\r\n";
	const char *cancel_msg = "501 5.0.0 auth exchange cancelled\r\n";

	testcase_setup_netwrite(test_netwrite);
	testcase_setup_net_readline(test_net_readline);
	testcase_ignore_log_write();

	auth_check = "/bin/false";
	auth_host = "foo.example.com";

	/* invalid AUTH mechanism */
	strcpy(linein, "AUTH BOGUS");
	linelen = strlen(linein);

	expected_net_write1 = "504 5.5.1 Unrecognized authentication type.\r\n";

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "unrecognized AUTH mechanism was not rejected\n");
		err++;
	}

	/* invalid base64 message */
	strcpy(linein, "AUTH PLAIN #");
	linelen = strlen(linein);

	expected_net_write1 = invalid_msg;

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH PLAIN with invalid base64 did not fail as expected\n");
		err++;
	}

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

	/* missing password */
	strcpy(linein, "AUTH PLAIN AGZvbwA=");
	linelen = strlen(linein);

	expected_net_write1 = invalid_msg;

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH PLAIN without password did not fail as expected\n");
		err++;
	}

	/* invalid base64 message */
	strcpy(linein, "AUTH LOGIN #");
	linelen = strlen(linein);

	expected_net_write1 = invalid_msg;

	if (smtp_auth() != EDONE) {
		fprintf(stderr, "AUTH LOGIN with invalid base64 did not fail as expected\n");
		err++;
	}

	return err;
}


pid_t fork_clean(void)
{
	exit(1);
	return -1;
}
