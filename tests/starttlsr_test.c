#include <qremote/qremote.h>
#include <qremote/starttlsr.h>
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

void
err_conf(const char *errmsg)
{
	fputs(errmsg, stderr);

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
	return 421;
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
	exit(EFAULT);
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

	/* this is what an SSL_library_exit() should do to reduce memcheck noise */
	ERR_remove_state(0);
	CONF_modules_unload(1);
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
}

int main(int argc, char **argv)
{
	if (argc > 2) {
		fprintf(stderr, "Usage: %s [partner_fqdn]\n", argv[0]);
		return EINVAL;
	} else if (argc == 2) {
		partner_fqdn = argv[1];
		rhost = partner_fqdn;
	} else {
		rhost = "[192.0.2.4]";
	}
	rhostlen = strlen(rhost);

	testcase_setup_netnwrite(test_netnwrite);
	testcase_setup_ssl_free(test_ssl_free);

	return tls_init();
}
