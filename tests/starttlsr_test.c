#include <qremote/qremote.h>
#include <qremote/starttlsr.h>
#include <ssl_timeoutio.h>
#include <tls.h>

#include "test_io/testcase_io.h"

#include <errno.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <unistd.h>

char *rhost;
size_t rhostlen;
char *partner_fqdn;
unsigned int smtpext;
string heloname;
static unsigned int conf_error_expected;
static int netget_result = 421;

void
err_conf(const char *errmsg)
{
	fputs("CONFIG error: ", stderr);
	fputs(errmsg, stderr);

	if (conf_error_expected)
		exit(0);
	else
		exit(EFAULT);
}

void
err_mem(const int k __attribute__((unused)))
{
	exit(ENOMEM);
}

void
write_status(const char *str)
{
	puts(str);
}

int
netget(void)
{
	return netget_result;
}

void
write_status_m(const char **strs, const unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count - 1; i++)
		fputs(strs[i], stdout);

	write_status(strs[count - 1]);
}

int
ssl_timeoutconn(time_t t __attribute__((unused)))
{
	if (netget_result == 220)
		return -1;
	exit(EFAULT);
}

const char *
test_ssl_strerror(void)
{
	return "expected error case";
}

void
test_net_conn_shutdown(const enum conn_shutdown_type sd_type __attribute__((unused)))
{
	if (ssl != NULL)
		ssl_free(ssl);
}

int
test_netnwrite(const char *s, const size_t len)
{
	const char *expect = "STARTTLS\r\n";

	if (strlen(expect) != len)
		exit(EFAULT);

	if (strncmp(s, expect, len) != 0)
		exit(EFAULT);

	return 0;
}

void
test_ssl_free(SSL *myssl)
{
	if (SSL_shutdown(myssl) == 0)
		SSL_shutdown(myssl);
	SSL_free(myssl);

	ssl_library_destroy();
}

void
ssl_library_destroy()
{
	ERR_remove_state(0);
	CONF_modules_unload(1);
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
}

const char *
test_ssl_error(void)
{
	return "expected SSL testcase error";
}

int main(int argc, char **argv)
{
	int r;

	if (argc > 3) {
		fprintf(stderr, "Usage: %s [partner_fqdn [netget_result]]\n", argv[0]);
		return EINVAL;
	} else if (argc >= 2) {
		partner_fqdn = argv[1];
		rhost = partner_fqdn;
		if (strstr(partner_fqdn, "bad") != NULL)
			testcase_setup_ssl_error(test_ssl_error);
		if (strstr(partner_fqdn, "conferror.") != NULL)
			conf_error_expected = 1;
		if (argc > 2) {
			netget_result = atoi(argv[2]);
			testcase_setup_ssl_strerror(test_ssl_strerror);
		}
	} else {
		rhost = "[192.0.2.4]";
	}
	rhostlen = strlen(rhost);

	testcase_setup_netnwrite(test_netnwrite);
	testcase_setup_ssl_free(test_ssl_free);
	testcase_setup_net_conn_shutdown(test_net_conn_shutdown);

	r = tls_init();

	test_net_conn_shutdown(shutdown_clean);

	return r;
}
