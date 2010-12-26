/** \file authsetup_test.c
 \brief Authentication setup testcases
 */

#include "qsauth.h"
#include "qsmtpd.h"
#include "sstring.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>

struct xmitstat xmitstat;
SSL *ssl = NULL;
unsigned long sslauth = 0;
char linein[1002];
size_t linelen;
char *auth_host = NULL;
char *auth_check = NULL;
char **auth_sub = NULL;

static const char loginonly[] = " LOGIN";
static const char plainonly[] = " PLAIN";
static const char loginplain[] = " LOGIN PLAIN";

static int
check_authstr(const char *auth_expect)
{
	char *auth_str = smtp_authstring();

	if (auth_str == NULL) {
		if (errno == 0) {
			const char *msg = "smtp_authstring() returned NULL but did not set an error code\n";
			write(2, msg, strlen(msg));
			return EFAULT;
		} else {
			return errno;
		}
	}

	if (strcmp(auth_str, auth_expect) != 0) {
		const char msg1[] = "smtp_authstring() returned \"";
		const char msg2[] = "\" instead of \"";
		const char msg3[] = "\"\n";

		write(2, msg1, strlen(msg1));
		write(2, auth_str, strlen(auth_str));
		write(2, msg2, strlen(msg2));
		write(2, auth_expect, strlen(auth_expect));
		write(2, msg3, strlen(msg3));

		free(auth_str);
		return 1;
	}

	free(auth_str);
	return 0;
}

static int
test_nocontrol(void)
{
#ifdef AUTHCRAM
	static const char auth_expect[] = " LOGIN PLAIN CRAM-MD5";
#else /* AUTHCRAM */
	static const char *auth_expect = loginplain;
#endif /* AUTHCRAM */

	return check_authstr(auth_expect);
}

static int
test_controlfiles(void)
{
	struct {
		const char *subdir;
		const char *expect;
	} patterns[] = {
		{
			.subdir = "login_only",
			.expect = loginonly
		},
		{
			.subdir = "plain_only",
			.expect = plainonly
		},
		{
			.subdir = "login_plain",
			.expect = loginplain
		},
		{
			.subdir = "duplicate_plain",
			.expect = plainonly
		},
		{
			.subdir = NULL,
			.expect = NULL
		}
	};
	unsigned int idx = 0;
	int errcnt = 0;

	while (patterns[idx].subdir != NULL) {
		if (chdir(patterns[idx].subdir) != 0) {
			const char *errmsg = "cannot chdir() to ";
			write(2, errmsg, strlen(errmsg));
			write(2, patterns[idx].subdir, strlen(patterns[idx].subdir));
			write(2, "\n", 1);
			errcnt++;
			idx++;
			continue;
		}

		if (check_authstr(patterns[idx].expect) != 0)
			errcnt++;

		if (chdir("..") != 0) {
			const char *errmsg = "cannot chdir() to back to start dir\n";
			write(2, errmsg, strlen(errmsg));
			errcnt++;
			idx++;
			continue;
		}
		idx++;
	}

	return errcnt;
}

static int
test_nonexistent(void)
{
	char *auth_str;

	if (chdir("nonexistent") != 0) {
		const char *errmsg = "cannot chdir() to \"nonexistent\"\n";
		write(2, errmsg, strlen(errmsg));
		return 1;
	}

	auth_str = smtp_authstring();

	if (auth_str != NULL) {
		const char errmsg1[] = "smtp_authstring() returned \"";
		const char errmsg2[] = "\" but is should have returned NULL\n";
		write(2, errmsg1, strlen(errmsg1));
		write(2, auth_str, strlen(auth_str));
		write(2, errmsg2, strlen(errmsg2));
		free(auth_str);
		return 1;
	}

	if (chdir("..") != 0) {
		const char *errmsg = "cannot chdir() to back to start dir\n";
		write(2, errmsg, strlen(errmsg));
		return 1;
	}

	return 0;
}


int main(int argc, char **argv)
{
	int errcnt = 0;

	if (argc != 2) {
		const char *errmsg = "required argument missing: base directory for control file tests\n";
		write(2, errmsg, strlen(errmsg));
		return EINVAL;
	}

	if (chdir(argv[1]) != 0) {
		const char *errmsg = "cannot chdir() to given directory\n";
		write(2, errmsg, strlen(errmsg));
		return -1;
	}

	memset(&xmitstat, 0, sizeof(xmitstat));
	memset(linein, 0, sizeof(linein));
	linelen = 0;

	if (test_nocontrol() != 0)
		errcnt++;

	errcnt += test_controlfiles();
	errcnt += test_nonexistent();

	return errcnt;
}

void log_writen(int priority __attribute__ ((unused)), const char **msg __attribute__ ((unused)))
{
}

inline void log_write(int priority __attribute__ ((unused)), const char *msg __attribute__ ((unused)))
{
}

int netwrite(const char *s __attribute__ ((unused)))
{
	return 0;
}

size_t net_readline(size_t num __attribute__ ((unused)), char *buf __attribute__ ((unused)))
{
	return 0;
}

pid_t fork_clean(void)
{
	return 1;
}

#undef _exit
void __attribute__ ((noreturn)) ssl_exit(int status)
{
	_exit(status);
}
