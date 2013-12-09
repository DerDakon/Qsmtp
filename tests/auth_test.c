/** \file auth_test.c
 \brief Authentication testcases
 */

#include "base64.h"
#include <qsmtpd/qsauth.h>
#include <qsmtpd/qsmtpd.h>
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

enum smtp_state {
	SMTP_AUTH,
	SMTP_USERNAME,
	SMTP_PASSWORD,
	SMTP_ACCEPT,
	SMTP_USERPASS,
	SMTP_REJECT
};

enum auth_mech {
	mech_login,
	mech_plain
};

static enum smtp_state smtpstate;
static enum auth_mech mech;
static unsigned int authstate;
static unsigned int authtry;
static int correct;

static int test_netnwrite(const char *s, const size_t len __attribute__((unused)))
{
	switch (smtpstate) {
	case SMTP_AUTH:
		if (strcmp("334 VXNlcm5hbWU6\r\n", s) != 0) {
			fprintf(stderr, "wrong SMTP message, awaited 'Username': %s", s);
			exit(1);
		}
		smtpstate = SMTP_USERNAME;
		return 0;
	case SMTP_USERNAME:
		if (strcmp("334 UGFzc3dvcmQ6\r\n", s) != 0) {
			fprintf(stderr, "wrong SMTP message, awaited 'Password': %s", s);
			exit(1);
		}
		smtpstate = SMTP_PASSWORD;
		return 0;
	case SMTP_PASSWORD:
		if (strncmp(s, "235 ", 4) == 0) {
			smtpstate = SMTP_ACCEPT;
		} else if (strncmp(s, "535 ", 4) == 0) {
			smtpstate = SMTP_REJECT;
		} else if ((authtry == 0) && (strncmp(s, "454 ", 4) == 0)) {
			smtpstate = SMTP_REJECT;
		} else {
			fprintf(stderr, "wrong SMTP message: %s", s);
			exit(1);
		}
		return 0;
	case SMTP_USERPASS:
		if (strcmp("334 \r\n", s) != 0) {
			fprintf(stderr, "wrong SMTP message, awaited '334 ': %s", s);
			exit(1);
		}
		smtpstate = SMTP_PASSWORD;
		return 0;
	default:
		exit(2);
	}
}

static size_t lineoffs;

static size_t
copy_chunk(const string *stin, size_t num, char *buf)
{
	string stout;
	size_t cplen;

	if (b64encode(stin, &stout, -1) != 0) {
		fprintf(stderr, "base64 encoding failed\n");
		exit(3);
	}

	cplen = stout.len + 2 - lineoffs;

	if (num >= cplen) {
		memcpy(buf, stout.s + lineoffs, cplen - 2);
		memcpy(buf + cplen - 2, "\r\n", 2);
	} else {
		memcpy(buf, stout.s + lineoffs, num);
		cplen = num;
	}

	free(stout.s);

	return cplen;
}

static size_t
encode_auth_login(size_t num, char *buf, const char *input)
{
	const string stin = {
		.s = (char *)input,
		.len = strlen(input)
	};

	return copy_chunk(&stin, num, buf);
}

static size_t
encode_auth_plain(size_t num, char *buf)
{
	char buffer[512];
	string stin;

	/* this should be ignored, test it with and without that data */
	memset(buffer, 'x', authtry);
	stin.len = authtry;
	buffer[stin.len++] = '\0';
	strcpy(buffer + stin.len, users[authtry].username);
	stin.len += strlen(users[authtry].username) + 1;
	if (correct) {
		strcpy(buffer + stin.len, users[authtry].password);
		stin.len += strlen(users[authtry].password);
	} else {
		/* send something random */
		strcpy(buffer + stin.len, "42");
		stin.len += 2;
	}
	stin.s = buffer;

	return copy_chunk(&stin, num, buf);
}

static size_t
test_net_readline(size_t num, char *buf)
{
	switch (authstate) {
	case 0:
	case 1:
	case 2:
	case 3: {
		const char *data;
		size_t ret;

		if ((authstate & 1) == 0)
			lineoffs = 0;

		switch (mech) {
		case mech_login:
			if (!correct || (authstate <= 1))
				data = users[authtry].username;
			else
				data = users[authtry].password;

			ret = encode_auth_login(num, buf, data);

			break;
		case mech_plain:
			ret = encode_auth_plain(num, buf);

			break;
		}

		data = memchr(buf, '\n', ret);

		if ((data != NULL) && (data < buf + ret - 1)) {
			fprintf(stderr, "AUTH buffer contains LF\n");
			exit(2);
		}

		lineoffs += ret;

		if ((authstate & 1) == 0)
			authstate++;
		/* if we did not use all the buffer we don't need a second try */
		if (ret < num)
			authstate++;

		return ret;
	}
	case 4:
		memcpy(buf, "\r\n", 2);
		authstate++;
		return 2;
	default: {
		const char *wrongauth = "unexpected call to net_readline()\n";
		write(2, wrongauth, strlen(wrongauth));
		exit(2);
	}
	}
}

static void
send_data_login(void)
{
	strcpy(linein, "AUTH LOGIN");

	if (authtry == 2) {
		strcat(linein, " ");
		encode_auth_login(sizeof(linein) - strlen(linein), linein + strlen(linein), users[authtry].username);

		smtpstate = SMTP_USERNAME;
		authstate = 2;
	}
}

static void
send_data_plain(void)
{
	strcpy(linein, "AUTH PLAIN");

	if (authtry == 2) {
		strcat(linein, " ");
		encode_auth_plain(sizeof(linein) - strlen(linein), linein + strlen(linein));

		smtpstate = SMTP_PASSWORD;
		authstate = 5;
	} else {
		smtpstate = SMTP_USERPASS;
		authstate = 0;
	}
}

int
main(int argc, char **argv)
{
	testcase_setup_netnwrite(test_netnwrite);
	testcase_setup_net_readline(test_net_readline);
	testcase_ignore_log_write();

	if (argc != 5) {
		fprintf(stderr, "usage: %s auth_dummy testname mechanism [correct|wrong]\n", argv[0]);
		return EINVAL;
	}

	/* call smtp_auth() before doing the AUTH setup, this should always fail. */
	if (smtp_auth() != 1) {
		fprintf(stderr, "smtp_auth() without auth_host set did not cause an error\n");
		return 1;
	}

	if (strcmp(argv[4], "correct") == 0) {
		correct = 1;
	} else if (strcmp(argv[4], "wrong") == 0) {
		correct = 0;
	} else {
		fprintf(stderr, "unrecognized last argument, must be 'wrong' or 'correct'\n");
		return EINVAL;
	}

	if (strcmp(argv[3], "LOGIN") == 0) {
		mech = mech_login;
	} else if (strcmp(argv[3], "PLAIN") == 0) {
		mech = mech_plain;
	} else {
		fprintf(stderr, "unrecognized mechanism argument, must be a supported SASL mechanism\n");
		return EINVAL;
	}

	auth_check = argv[1];
	auth_host = "foo.example.com";
	auth_sub = malloc(sizeof(*auth_sub) * 2);
	auth_sub[0] = autharg;
	auth_sub[1] = NULL;

	while (users[authtry].testname != NULL) {
		int errcnt = 0;
		int i;

		if (strcmp(users[authtry].testname, argv[2]) != 0) {
			authtry++;
			continue;
		}

		memset(&xmitstat, 0, sizeof(xmitstat));
		memset(linein, 0, sizeof(linein));

		printf("testing mechanism %s, user \"%s\" with %s password\n",
				argv[3], users[authtry].username, argv[4]);

		smtpstate = SMTP_AUTH;
		authstate = 0;

		switch (mech) {
		case mech_login:
			send_data_login();
			break;
		case mech_plain:
			send_data_plain();
			break;
		}

		linelen = strlen(linein);

		i = smtp_auth();
		/* every even try will test a failed authentication */
		if (correct) {
			if (i != 0)
				fprintf(stderr, "SMTP problem, error code %i\n", i);
			if (smtpstate != SMTP_ACCEPT) {
				fprintf(stderr, "authentication failed unexpected\n");
				errcnt++;
			} else if ((xmitstat.authname.len == 0) || (xmitstat.authname.s == NULL)) {
				fprintf(stderr, "name of authenticated user was not set\n");
				errcnt++;
			} else if (strcmp(xmitstat.authname.s, users[authtry].username) != 0) {
				fprintf(stderr, "authenticated user name %s does not match expected %s\n",
						xmitstat.authname.s, users[authtry].username);
				errcnt++;
			}

			/* Call smtp_auth() again. Since a user is already authenticated this
			 * must result in an error. */
			if (smtp_auth() != 1) {
				fprintf(stderr, "duplicate authentication did not return an error\n");
				errcnt++;
			}
		} else {
			if (i != EDONE)
				fprintf(stderr, "SMTP problem, error code %i\n", i);
			if (smtpstate != SMTP_REJECT) {
				fprintf(stderr, "authentication succeeded unexpected\n");
				errcnt++;
			}
		}

		free(xmitstat.authname.s);
		free(auth_sub);

		return errcnt;
	}

	fprintf(stderr, "unrecognized test name\n");
	return EINVAL;
}

pid_t fork_clean(void)
{
	return fork();
}

void
tarpit(void)
{
}
