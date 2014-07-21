/** \file tls.h
 \brief global SSL error handling definitions
 */
#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>

extern SSL *ssl;

void ssl_free(SSL *myssl);
void ssl_exit(int status) __attribute__ ((noreturn));

void ssl_library_destroy();

const char *ssl_error(void);
const char *ssl_strerror(void);

#endif
