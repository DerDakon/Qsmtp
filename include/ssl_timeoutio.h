#ifndef SSL_TIMEOUTIO_H
#define SSL_TIMEOUTIO_H

#include <openssl/ssl.h>
#include <time.h>

/* the version is like this: 0xMNNFFPPS: major minor fix patch status */
#if OPENSSL_VERSION_NUMBER < 0x00906030L
# error "Need OpenSSL version at least 0.9.6c"
#endif

extern int ssl_timeoutconn(time_t);
extern int ssl_timeoutaccept(time_t);
extern int ssl_timeoutrehandshake(time_t);
extern int ssl_rfd;
extern int ssl_wfd;

extern int ssl_timeoutread(time_t, char *, const int);
extern inline int ssl_timeoutwrite(time_t, const char *, const int);

extern int ssl_timeoutio(int (*fun)(), time_t, char *, int) __attribute__ ((nonnull (1)));

#endif
