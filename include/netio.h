#ifndef NETIO_H
#define NETIO_H

#include <bits/wordsize.h>
#include <sys/types.h>

extern char linein[];			/* current input line */
extern size_t linelen;			/* length of the line */

extern int net_read(void);
extern int net_writen(const char *const *);
extern inline int netwrite(const char *);	/* same as net_write but expects that line is <= 512 characters
						 * and includes <CRLF> */
extern int netnwrite(const char *, const size_t);
extern void ultostr(const unsigned long u, char *);
extern size_t net_readbin(size_t, char *);
extern size_t net_readline(size_t, char *);
extern int data_pending(void);

static inline int
net_write(const char *s)
{
	const char *msg[] = {s, "\r\n", NULL};
	return net_writen(msg);
}

#if __WORDSIZE == 64
#define ULSTRLEN 21
#else
#define ULSTRLEN 11
#endif

extern unsigned long timeout;
extern int socketd;

#endif
