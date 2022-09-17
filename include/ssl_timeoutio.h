/** \file ssl_timeoutio.h
 \brief definition of wrappers around OpenSSL functions
 */
#ifndef SSL_TIMEOUTIO_H
#define SSL_TIMEOUTIO_H

#include <openssl/ssl.h>
#include <time.h>

extern int ssl_timeoutconn(SSL *s, time_t t);
extern int ssl_timeoutaccept(SSL *s, time_t t);
extern int ssl_timeoutrehandshake(SSL *s, time_t t);

extern int ssl_timeoutread(SSL *s, time_t t, char *buf, const int len);
extern int ssl_timeoutwrite(SSL *s, time_t t, const char *buf, const int len);

#endif
