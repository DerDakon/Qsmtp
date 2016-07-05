/** \file authsetup_test.c
 \brief Authentication setup testcases
 */

#include <control.h>
#include <diropen.h>
#include <log.h>
#include <netio.h>
#include <qsmtpd/qsauth.h>
#include <qsmtpd/qsauth_backend.h>
#include <qsmtpd/qsmtpd.h>
#include <sstring.h>
#include "test_io/testcase_io.h"

#include <fcntl.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

struct xmitstat xmitstat;
unsigned long sslauth = 0;

static const char loginonly[] = " LOGIN\r\n";
static const char plainonly[] = " PLAIN\r\n";
static const char loginplain[] = " LOGIN PLAIN\r\n";

static const char *argv_auth[] = { "Qsmtpd", "auth.example.com", NULL };
static const char *argv_noauth[] = { "Qsmtpd" };

int
auth_backend_execute(const struct string *user __attribute__((unused)),
		const struct string *pass __attribute__((unused)), const struct string *resp __attribute__((unused)))
{
	fprintf(stderr, "unexpected call to %s()\n", __func__);
	exit(1);
}

static const char backend_setup_errmsg[] = "auth_backend_setup() error";

int
auth_backend_setup(int argc,
		const char **argv __attribute__((unused)))
{
	if (argc == 3)
		return 0;

	log_write(LOG_ERR, backend_setup_errmsg);
	return -EINVAL;
}

static int
check_authstr(const char *auth_expect)
{
	char *auth_str = smtp_authstring();

	if (auth_str == NULL) {
		if (errno == 0) {
			fprintf(stderr, "smtp_authstring() returned NULL but did not set an error code, "
					"expected message '%s'\n", auth_expect);
			return EFAULT;
		} else {
			return errno;
		}
	}

	if (strcmp(auth_str, auth_expect) != 0) {
		fprintf(stderr, "smtp_authstring() returned \"%s\" instead of \"%s\"\n",
				auth_str, auth_expect);

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
	static const char auth_expect[] = " LOGIN PLAIN CRAM-MD5\r\n";
#else /* AUTHCRAM */
	static const char *auth_expect = loginplain;
#endif /* AUTHCRAM */

	controldir_fd = AT_FDCWD;
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
		{ }
	};
	unsigned int idx = 0;
	int errcnt = 0;

	while (patterns[idx].subdir != NULL) {
		char fnbuf[strlen("/control") + strlen(patterns[idx].subdir) + 1];

		snprintf(fnbuf, sizeof(fnbuf), "%s/control", patterns[idx].subdir);
		controldir_fd = open(fnbuf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (controldir_fd < 0) {
			fprintf(stderr, "cannot open(%s): %s\n",
					patterns[idx].subdir, strerror(errno));
			errcnt++;
			idx++;
			continue;
		}

		if (check_authstr(patterns[idx].expect) != 0)
			errcnt++;

		close(controldir_fd);
		idx++;
	}

	return errcnt;
}

static int
test_nonexistent(void)
{
	const char found_garbage[] = "error: unknown auth type \"garbage\" found in control/authtypes";
	int ret = 0;

	if (chdir("nonexistent") != 0) {
		fputs("cannot chdir() to \"nonexistent\"\n", stderr);
		return 1;
	}

	controldir_fd = get_dirfd(AT_FDCWD, "control");

	testcase_setup_log_writen(testcase_log_writen_combine);
	log_write_msg = found_garbage;
	log_write_priority = LOG_ERR;

	char *auth_str = smtp_authstring();

	close(controldir_fd);

	if (auth_str != NULL) {
		fprintf(stderr, "%s: smtp_authstring() returned \"%s\" but is should have returned NULL\n",
				__func__, auth_str);
		free(auth_str);
		ret++;
	}

	if (log_write_msg != NULL) {
		fprintf(stderr, "%s: smtp_authstring() did not write the expected error message\n", __func__);
		ret++;
	}

	if (chdir("..") != 0) {
		fprintf(stderr, "cannot chdir(..): %s\n",
				strerror(errno));
		ret++;
	}

	return ret;
}

static int
test_loaderror(void)
{
	int ret = 0;

	controldir_fd = -1;

	/* no message expected, but this will bail out if one comes */
	testcase_setup_log_writen(testcase_log_writen_combine);

	char *auth_str = smtp_authstring();

	if (errno != EBADF) {
		fprintf(stderr, "%s: smtp_authstring() returned error %i but is should have returned %i (EBADF)\n",
			__func__, errno, EBADF);
		ret++;
	}

	if (auth_str != NULL) {
		fprintf(stderr, "%s: smtp_authstring() returned \"%s\" but is should have returned NULL\n",
				__func__, auth_str);
		free(auth_str);
		ret++;
	}

	return ret;
}

static int
test_no_auth_yet(void)
{
	int ret = 0;

	auth_setup(1, argv_noauth);
	char *authstr = smtp_authstring();
	if (authstr != NULL) {
		fprintf(stderr, "smtp_authstring() with auth_host == NULL returned string %s instead of NULL\n",
				authstr);
		free(authstr);
		ret++;
	}

	auth_setup(3, argv_auth);
	sslauth = 1;
	authstr = smtp_authstring();
	if (authstr != NULL) {
		fprintf(stderr, "smtp_authstring() with sslauth == 1 and ssl == NULL returned string %s instead of NULL\n",
				authstr);
		free(authstr);
		ret++;
	}

	sslauth = 0;

	return ret;
}

static int
test_setup_errors(void)
{
	int ret = 0;
	const char err_invalid_domain[] = "domainname for auth invalid: @";
	const char *args_invalid_domain[] = { "Qsmtpd", "@", NULL };

	sslauth = 0;
	auth_setup(3, argv_auth);
	if (!auth_permitted()) {
		fprintf(stderr, "auth_permitted() after correct auth_setup() returned 0\n");
		return ++ret;
	}

	testcase_setup_log_writen(testcase_log_writen_combine);

	log_write_msg = err_invalid_domain;
	log_write_priority = LOG_WARNING;
	auth_setup(3, args_invalid_domain);

	if (auth_permitted()) {
		fprintf(stderr, "auth_permitted() after incorrect auth_setup() returned 1\n");
		ret++;
	}

	if (log_write_msg != NULL) {
		fprintf(stderr, "%s: smtp_authstring() did not write the expected error message\n", __func__);
		log_write_msg = NULL;
		ret++;
	}

	auth_setup(3, argv_auth);
	if (!auth_permitted()) {
		fprintf(stderr, "auth_permitted() after correct auth_setup() returned 0\n");
		return ++ret;
	}

	/* this will cause auth_backend_setup() to return with failure */
	testcase_setup_log_writen(testcase_log_writen_combine);
	log_write_msg = backend_setup_errmsg;
	log_write_priority = LOG_ERR;
	auth_setup(2, argv_auth);

	if (auth_permitted()) {
		fprintf(stderr, "auth_permitted() after incorrect auth_setup() returned 1\n");
		ret++;
	}

	if (log_write_msg != NULL) {
		fprintf(stderr, "%s: smtp_authstring() did not write the expected error message\n", __func__);
		log_write_msg = NULL;
		ret++;
	}

	testcase_ignore_log_writen();

	return ret;
}

int main(int argc, char **argv)
{
	int errcnt = 0;

	testcase_setup_log_write(testcase_log_write_compare);
	testcase_ignore_log_writen();

	if (argc != 2) {
		fputs("required argument missing: base directory for control file tests\n", stderr);
		return EINVAL;
	}

	auth_setup(3, argv_auth);

	if (chdir(argv[1]) != 0) {
		fprintf(stderr, "cannot chdir(%s): %s\n", argv[1], strerror(errno));
		return -1;
	}

	memset(&xmitstat, 0, sizeof(xmitstat));
	linein.len = 0;

	if (test_nocontrol() != 0)
		errcnt++;

	errcnt += test_controlfiles();
	errcnt += test_nonexistent();
	errcnt += test_loaderror();
	errcnt += test_no_auth_yet();
	errcnt += test_setup_errors();

	return errcnt;
}

void
tarpit(void)
{
}
