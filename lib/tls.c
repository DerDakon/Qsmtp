#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls.h"

SSL *ssl = NULL;

void ssl_free(SSL *myssl) { SSL_shutdown(myssl); SSL_free(myssl); }
void __attribute__ ((noreturn)) ssl_exit(int status) { if (ssl) ssl_free(ssl); _exit(status); }

const char *ssl_error(void)
{
	unsigned long r = ERR_get_error();

	if (!r)
		return NULL;
	SSL_load_error_strings();
	return ERR_error_string(r, NULL);
}

const char *ssl_strerror(void)
{
	const char *err = ssl_error();

	if (err)
		return err;
	if (!errno)
		return NULL;
	return (errno == ETIMEDOUT) ? "timed out" : strerror(errno);
}
