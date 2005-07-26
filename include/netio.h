#ifndef NETIO_H
#define NETIO_H

#include <bits/wordsize.h>
#include <sys/types.h>
#include <time.h>

extern char linein[];
extern size_t linelen;

extern int net_read(void);
extern int net_writen(const char *const *) __attribute__ ((nonnull (1)));
extern inline int netwrite(const char *) __attribute__ ((nonnull (1)));
extern int netnwrite(const char *, const size_t) __attribute__ ((nonnull (1)));
extern void ultostr(const unsigned long u, char *) __attribute__ ((nonnull (2)));
extern size_t net_readbin(size_t, char *) __attribute__ ((nonnull (2)));
extern size_t net_readline(size_t, char *) __attribute__ ((nonnull (2)));
extern int data_pending(void);

static inline int __attribute__ ((nonnull (1)))
net_write(const char *s)
{
	const char *msg[] = {s, "\r\n", NULL};
	return net_writen(msg);
}

/** \def ULSTRLEN
 \brief length of the ascii representation of an unsigned long
 */
#if __WORDSIZE == 64
#define ULSTRLEN 21
#else
#define ULSTRLEN 11
#endif

extern time_t timeout;
extern int socketd;

#ifdef DEBUG_IO
extern int do_debug_io;
extern int in_data;
#endif

#endif
