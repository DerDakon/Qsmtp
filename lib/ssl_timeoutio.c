/** \file ssl_timeoutio.c
 \brief SSL encoding and decoding functions for network I/O
 */
#include <sys/select.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include "ssl_timeoutio.h"
#include "log.h"
#include "tls.h"

#define ndelay_on(fd) fcntl(fd,F_SETFL,fcntl(fd,F_GETFL) | O_NONBLOCK)
#define ndelay_off(fd) fcntl(fd,F_SETFL,fcntl(fd,F_GETFL) & ~O_NONBLOCK)

static int ssl_timeoutio(int (*fun)(), time_t, char *, int) __attribute__ ((nonnull (1)));
/**
 * call SSL function for given data buffer
 *
 * @param fun OpenSSL function to call
 * @param t timeout
 * @param buf data buffer
 * @param len length of buf
 * @return return code of fun
 *
 * on timeout program is terminated
 */
static int
ssl_timeoutio(int (*fun)(), time_t t, char *buf, const int len)
{
	int n = 0;
	const time_t end = t + time(NULL);
	int fd = -1;

	do {
		fd_set fds;
		struct timeval tv;
		const int r = buf ? fun(ssl, buf, len) : fun(ssl);

		if (r > 0)
			return r;

		t = end - time(NULL);
		if (t < 0)
			break;
		tv.tv_sec = t;
		tv.tv_usec = 0;

		FD_ZERO(&fds);
		switch (SSL_get_error(ssl, r)) {
		case SSL_ERROR_WANT_READ:
			if (fd < 0) {
				fd = SSL_get_rfd(ssl);
				assert(fd >= 0);
			}
			FD_SET(fd, &fds);
			n = select(fd + 1, &fds, NULL, NULL, &tv);
			break;
		case SSL_ERROR_WANT_WRITE:
			if (fd < 0) {
				fd = SSL_get_wfd(ssl);
				assert(fd >= 0);
			}
			FD_SET(fd, &fds);
			n = select(fd + 1, NULL, &fds, NULL, &tv);
			break;
		default:
			return r; /* some other error */
		}

		/* n is the number of descriptors that changed status */
	} while (n > 0);

	if (!n)
		dieerror(ETIMEDOUT);

	return n;
}

int
ssl_timeoutaccept(time_t t)
{
	int r;
	int ssl_wfd = SSL_get_wfd(ssl);
	int ssl_rfd = SSL_get_rfd(ssl);

	/* if connection is established, keep NDELAY */
	if (ndelay_on(ssl_rfd) == -1 || ndelay_on(ssl_wfd) == -1)
		return -1;
	r = ssl_timeoutio(SSL_accept, t, NULL, 0);

	if (r <= 0) {
		r = ndelay_off(ssl_rfd);
		if (!r)
			r = ndelay_off(ssl_wfd);
	} else
		SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);

	return r;
}

int
ssl_timeoutconn(time_t t)
{
	int r;
	int ssl_wfd = SSL_get_wfd(ssl);
	int ssl_rfd = SSL_get_rfd(ssl);

	/* if connection is established, keep NDELAY */
	if ( (ndelay_on(ssl_rfd) == -1) || (ndelay_on(ssl_wfd) == -1) )
		return -1;
	r = ssl_timeoutio(SSL_connect, t, NULL, 0);

	if (r <= 0) {
		r = ndelay_off(ssl_rfd);
		if (!r)
			r = ndelay_off(ssl_wfd);
	} else {
		SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
	}

	return r;
}

int
ssl_timeoutrehandshake(time_t t)
{
	int r;

	SSL_renegotiate(ssl);
	r = ssl_timeoutio(SSL_do_handshake, t, NULL, 0);
	if (r <= 0 || ssl->type == SSL_ST_CONNECT)
		return r;

	/* this is for the server only */
	ssl->state = SSL_ST_ACCEPT;
	return ssl_timeoutio(SSL_do_handshake, t, NULL, 0);
}

int ssl_timeoutread(time_t t, char *buf, const int len)
{
	if (SSL_pending(ssl))
		return SSL_read(ssl, buf, len);
	return ssl_timeoutio(SSL_read, t, buf, len);
}

/**
 * write data SSL encrypted to network
 *
 * @param t timeout
 * @param buf data to send
 * @param len length of buf
 * @return return code of SSL_write
 */
inline int
ssl_timeoutwrite(time_t t, const char *buf, const int len)
{
	/* SSL_write takes a const char* as second argument so
	 * we do not need to worry here, just shut up the compiler */
	return ssl_timeoutio(SSL_write, t, (char *)buf, len);
}
