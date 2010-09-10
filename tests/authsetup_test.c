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

#ifdef AUTHCRAM
static const char *auth_expect = " LOGIN PLAIN CRAM-MD5";
#else /* AUTHCRAM */
static const char *auth_expect = " LOGIN PLAIN";
#endif /* AUTHCRAM */

int main(void)
{
	int errcnt = 0;
	char *auth_str;

	memset(&xmitstat, 0, sizeof(xmitstat));
	memset(linein, 0, sizeof(linein));
	linelen = 0;

	auth_str = smtp_authstring();

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
		const char msg1 = "smtp_authstring() returned \"";
		const char msg2 = "\" instead of \"";
		const char msg3 = "\"\n";

		write(2, msg1, strlen(msg1));
		write(2, auth_str, strlen(auth_str));
		write(2, msg2, strlen(msg2));
		write(2, auth_expect, strlen(auth_expect));
		write(2, msg3, strlen(msg3));

		return 1;
	}

	return 0;
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
