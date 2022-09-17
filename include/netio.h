/** \file netio.h
 \brief functions for network I/O
 */
#ifndef NETIO_H
#define NETIO_H

#include "compiler.h"
#include "sstring.h"

#include <openssl/ssl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

extern struct string linein;

extern int net_read(const int fatal);
extern int net_writen(const char *const *) __attribute__ ((nonnull (1)));
extern int net_write_multiline(const char *const *) __attribute__ ((nonnull (1)));
static inline int netwrite(const char *) __attribute__ ((nonnull (1)));
extern int netnwrite(const char *, const size_t) __attribute__ ((nonnull (1))) ATTR_ACCESS(read_only, 1, 2);
extern size_t net_readbin(size_t, char *) __attribute__ ((nonnull (2))) ATTR_ACCESS(read_write, 2, 1);
extern size_t net_readline(size_t, char *) __attribute__ ((nonnull (2))) ATTR_ACCESS(read_write, 2, 1);
extern int data_pending(SSL *s);

extern time_t timeout;
extern int socketd;

enum conn_shutdown_type {
	shutdown_clean,		/**< do a normal shutdown and notify the partner about the shutdown */
	shutdown_abort		/**< do hard abort of connection */
};

/**
 * \brief shutdown the connection and end the program
 * \param sd_type specifies the way the shutdown should be performed
 *
 * This is a forward declaration only, every program has to implement
 * this function in a way that matches how it works.
 *
 * A shutdown_clean shutdown is e.g. sending QUIT to the server and waiting for it's
 * reply. A shutdown with shutdown_abort is e.g. hard dropping of the connection if
 * the client sends spam and has a broken SMTP engine that does not react to error codes.
 *
 * Calling this function even before the connection was established is fine.
 */
extern void net_conn_shutdown(const enum conn_shutdown_type sd_type) __attribute__ ((noreturn));

#ifdef DEBUG_IO
extern int do_debug_io;
extern int in_data;
#endif

static inline int
netwrite(const char *s)
{
	return netnwrite(s, strlen(s));
}

#endif
