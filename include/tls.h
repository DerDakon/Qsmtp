#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>

extern SSL *ssl;

void ssl_free(SSL *myssl);
void __attribute__ ((noreturn)) ssl_exit(int status);
# define _exit ssl_exit

const char *ssl_error(void);
const char *ssl_strerror(void);

#endif
