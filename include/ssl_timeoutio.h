#ifndef SSL_TIMEOUTIO_H
#define SSL_TIMEOUTIO_H

#include <openssl/ssl.h>

/* the version is like this: 0xMNNFFPPS: major minor fix patch status */
#if OPENSSL_VERSION_NUMBER < 0x00906000L
# error "Need OpenSSL version at least 0.9.6"
#endif

extern int ssl_timeoutconn(long t);
extern int ssl_timeoutaccept(long t);
extern int ssl_timeoutrehandshake(long t);
extern int ssl_rfd;
extern int ssl_wfd;

extern int ssl_timeoutread(long t, char *buf, const int len);
extern inline int ssl_timeoutwrite(long t, const char *buf, const int len);

extern int ssl_timeoutio(int (*fun)(), long t, char *buf, int len);

#endif
