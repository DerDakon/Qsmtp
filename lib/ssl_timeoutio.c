/** \file ssl_timeoutio.c
 \brief SSL encoding and decoding functions for network I/O
 */

#include <ssl_timeoutio.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <openssl/err.h>
#include <stdbool.h>

#define ndelay_on(fd)  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
#define ndelay_off(fd) (void) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK)

/**
 * call SSL function for given data buffer
 *
 * @param func OpenSSL function to call
 * @param t timeout
 * @param buf data buffer
 * @param len length of buf
 * @return if call to func was successful
 * @retval >0 the call was successful
 * @retval <0 error code
 * @retval -EPROTO there was a SSL-level protocol error
 *
 * This function never returns 0.
 */
static int __attribute__ ((nonnull (1)))
ssl_timeoutio(int (*func)(), SSL *s, time_t t, char *buf, const int len)
{
	int n = 0;
	const time_t end = t + time(NULL);
	struct pollfd fds[2] = {
		{
			.fd = SSL_get_rfd(s),
			.events = POLLIN
		},
		{
			.fd = SSL_get_wfd(s),
			.events = POLLOUT
		}
	};

	assert(fds[0].fd >= 0);
	assert(fds[1].fd >= 0);

	do {
		errno = 0;
		int r = buf ? func(s, buf, len) : func(s);

		if (r > 0)
			return r;

		t = (end - time(NULL)) * 1000;
		/* If the timeout expired look again if there is a pending
		 * transmission right now, otherwise fail the normal way. */
		if (t < 0)
			t = 0;

		switch (SSL_get_error(s, r)) {
		case SSL_ERROR_WANT_READ:
			n = poll(fds, 1, t);
			break;
		case SSL_ERROR_WANT_WRITE:
			n = poll(fds + 1, 1, t);
			break;
		case SSL_ERROR_ZERO_RETURN:
			return -ECONNRESET;
		case SSL_ERROR_SYSCALL:
			if (ERR_get_error() == 0) {
				switch (r) {
				case -1:
					/* OpenSSL docs say it is set */
					assert(errno != 0);
					return -errno;
				case 0:
					return -ECONNRESET;
				}
			}
			/* fallthrough */
		default:
			return -EPROTO; /* some other error */
		}

		/* n is the number of descriptors that changed status */
	} while (n > 0);

	if (n == 0)
		return -ETIMEDOUT;

	assert(errno != 0);
	return -errno;
}

/**
 * @brief accept the request for SSL
 * @param t timeout in seconds
 * @return if the call was successful
 * @retval 0 the call was successful
 * @retval <0 error code
 */
int
ssl_timeoutaccept(SSL *s, time_t t)
{
	int ssl_wfd = SSL_get_wfd(s);
	int ssl_rfd = SSL_get_rfd(s);

	/* if connection is established, keep NDELAY */
	if (ndelay_on(ssl_rfd) == -1 || ndelay_on(ssl_wfd) == -1)
		return -errno;
	int r = ssl_timeoutio(SSL_accept, s, t, NULL, 0);

	if (r < 0) {
		ndelay_off(ssl_rfd);
		ndelay_off(ssl_wfd);
		return r;
	} else {
		return 0;
	}
}

/**
 * @brief establish SSL protocol to remote host
 * @param t timeout in seconds
 * @return if the call was successful
 * @retval 0 the call was successful
 * @retval <0 error code
 */
int
ssl_timeoutconn(SSL *s, time_t t)
{
	int ssl_wfd = SSL_get_wfd(s);
	int ssl_rfd = SSL_get_rfd(s);

	/* if connection is established, keep NDELAY */
	if ( (ndelay_on(ssl_rfd) == -1) || (ndelay_on(ssl_wfd) == -1) )
		return -errno;
	int r = ssl_timeoutio(SSL_connect, s, t, NULL, 0);

	if (r < 0) {
		/* keep nonblocking, the socket is closed anyway */
		return r;
	} else {
		return 0;
	}
}

/**
 * @brief do a new SSL handshake
 * @param t timeout in seconds
 * @return if handshake was successful
 * @retval >0 handshake was successful
 * @retval <0 error code
 */
int
ssl_timeoutrehandshake(SSL *s, time_t t)
{
	int r;
#ifdef TLS1_3_VERSION
	bool tls13 = false;
	if (SSL_version(s) >= TLS1_3_VERSION) {
		tls13 = true;
		if (SSL_verify_client_post_handshake(s) != 1)
			return -EPROTO;
		} else
#endif
	{
		r = SSL_renegotiate(s);
		if (r <= 0)
			return -EPROTO;
	}
	r = ssl_timeoutio(SSL_do_handshake, s, t, NULL, 0);
	if (r < 0)
		return r;

#ifdef TLS1_3_VERSION
	if (tls13)
		return 0;
#endif

	/* this is for the server only */
	SSL_set_accept_state(s);
	return ssl_timeoutio(SSL_do_handshake, s, t, NULL, 0);
}

int ssl_timeoutread(SSL *s, time_t t, char *buf, const int len)
{
	return ssl_timeoutio(SSL_read, s, t, buf, len);
}

/**
 * write data SSL encrypted to network
 *
 * @param t timeout
 * @param buf data to send
 * @param len length of buf
 * @return return code of SSL_write
 */
int
ssl_timeoutwrite(SSL *s, time_t t, const char *buf, const int len)
{
	/* SSL_write takes a const char* as second argument so
	 * we do not need to worry here, just shut up the compiler */
	return ssl_timeoutio(SSL_write, s, t, (char *)buf, len);
}
