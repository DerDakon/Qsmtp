/** \file ssl_timeoutio.h
 \brief definition of wrappers around OpenSSL functions
 */
#ifndef SSL_TIMEOUTIO_H
#define SSL_TIMEOUTIO_H

#include <openssl/ssl.h>
#include <time.h>

extern int ssl_timeoutconn(time_t);
extern int ssl_timeoutaccept(time_t);
extern int ssl_timeoutrehandshake(time_t);

extern int ssl_timeoutread(time_t, char *, const int);
extern int ssl_timeoutwrite(time_t, const char *, const int);

#endif
