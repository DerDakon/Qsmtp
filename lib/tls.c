/** \file tls.c
 \brief helper functions for STARTTLS
 */
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "tls.h"

SSL *ssl = NULL;

void ssl_free(SSL *myssl)
{
	if (SSL_shutdown(myssl) == 0)
		SSL_shutdown(myssl);
	SSL_free(myssl);

	ssl_library_destroy();
}

/* _exit is defined to ssl_exit in tls.h to be sure ssl is always freed correctly */
#undef _exit
void __attribute__ ((noreturn)) ssl_exit(int status)
{
	if (ssl)
		ssl_free(ssl);
	_exit(status);
}

/**
 * @brief free internal check memory of the SSL library
 *
 * This would ideally be a function of the SSL library, but it is not.
 */
void
ssl_library_destroy()
{
	ERR_remove_state(0);
	CONF_modules_unload(1);
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
}

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
