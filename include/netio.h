/** \file netio.h
 \brief functions for network I/O
 */
#ifndef NETIO_H
#define NETIO_H

#include <sys/types.h>
#include <time.h>

extern char linein[];
extern size_t linelen;

extern int net_read(void);
extern int net_writen(const char *const *) __attribute__ ((nonnull (1)));
extern int netwrite(const char *) __attribute__ ((nonnull (1)));
extern int netnwrite(const char *, const size_t) __attribute__ ((nonnull (1)));
extern size_t net_readbin(size_t, char *) __attribute__ ((nonnull (2)));
extern size_t net_readline(size_t, char *) __attribute__ ((nonnull (2)));
extern int data_pending(void);

static inline int __attribute__ ((nonnull (1)))
net_write(const char *s)
{
	const char *msg[] = {s, "\r\n", NULL};
	return net_writen(msg);
}

extern time_t timeout;
extern int socketd;

#ifdef DEBUG_IO
extern int do_debug_io;
extern int in_data;
#endif

#endif
