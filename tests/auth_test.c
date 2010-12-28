/** \file authsetup_test.c
 \brief Authentication setup testcases
 */

#include "base64.h"
#include "qsauth.h"
#include "qsmtpd.h"
#include "sstring.h"

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
const char *auth_host = "foo.example.com";
const char *auth_check;
const char **auth_sub;

enum smtp_state {
	SMTP_AUTH,
	SMTP_USERNAME,
	SMTP_PASSWORD,
	SMTP_ACCEPT,
	SMTP_REJECT
};

static enum smtp_state smtpstate;
static unsigned int authstate;
static unsigned int authtry;
static int correct;

int
main(int argc, char **argv)
{
	if (argc < 2) {
		fputs("required argument missing: name of auth dummy program\n", stderr);
		return EINVAL;
	}
	if (argc != 4) {
		fprintf(stderr, "usage: %s auth_dummy testname [correct|wrong]\n", argv[0]);
		return EINVAL;
	}

	auth_check = argv[1];
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

		if (strcmp(argv[3], "correct") == 0) {
			correct = 1;
		} else if (strcmp(argv[3], "wrong") == 0) {
			correct = 0;
		} else {
			fprintf(stderr, "unrecognized last argument, must be 'wrong' or 'correct'\n");
			return EINVAL;
		}

		memset(&xmitstat, 0, sizeof(xmitstat));
		memset(linein, 0, sizeof(linein));

		strcpy(linein, "AUTH LOGIN");
		linelen = strlen(linein);

		smtpstate = SMTP_AUTH;
		authstate = 0;

		printf("testing user \"%s\" with %s password\n", users[authtry].username, argv[3]);

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

void log_writen(int priority __attribute__ ((unused)), const char **msg __attribute__ ((unused)))
{
}

inline void log_write(int priority __attribute__ ((unused)), const char *msg __attribute__ ((unused)))
{
}

int netwrite(const char *s)
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
		} else {
			fprintf(stderr, "wrong SMTP message: %s", s);
			exit(1);
		}
		return 0;
	default:
		exit(2);
	}
}

static size_t lineoffs;

static
size_t authline(size_t num, char *buf, const char *input)
{
	const string stin = {
		.s = (char *)input,
		.len = strlen(input)
	};
	string stout;
	size_t cplen;

	if (b64encode(&stin, &stout) != 0)
		exit(3);

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

size_t net_readline(size_t num, char *buf)
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

		if (!correct || (authstate <= 1))
			data = users[authtry].username;
		else
			data = users[authtry].password;

		ret = authline(num, buf, data);

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

pid_t fork_clean(void)
{
	return fork();
}

#undef _exit
void __attribute__ ((noreturn)) ssl_exit(int status)
{
	_exit(status);
}
