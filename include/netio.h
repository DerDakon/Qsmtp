#ifndef NETIO_H
#define NETIO_H

extern char linein[];			/* current input line */
extern unsigned int linelen;		/* length of the line */

extern int net_read(void);
extern int net_writen(const char *const *);
extern int netwrite(const char *);	/* same as net_write but expects that line is <= 512 characters
					 * and includes <CRLF> */
extern char *ultostr(const unsigned long u);
extern int net_readbin(unsigned int, char *, const int);
extern int data_pending(void);

static inline int
net_write(const char *s)
{
	const char *msg[] = {s, "\r\n", NULL};
	return net_writen(msg);
}

extern unsigned long timeout;

#endif
