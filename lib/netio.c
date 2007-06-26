/** \file netio.c
 \brief functions for network I/O
 */
#include <sys/select.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "netio.h"
#include "log.h"
#include "ssl_timeoutio.h"
#include "tls.h"

char linein[1002];			/**< buffer for the line to read: max 1000 chars including CRLF,
					 * leading extra '.', closing '\\0' */
size_t linelen;				/**< length of the line */
static char lineinn[sizeof(linein)];	/**< if more than one line was in linein the rest is stored here */
size_t linenlen;			/**< length of the lineinn */
time_t timeout;				/**< how long to wait for data */

#ifdef DEBUG_IO
#include <syslog.h>

int do_debug_io;
int in_data;

void DEBUG_IN(const size_t len)
{
	char buffer[len + 4];
	size_t en = 0;
	size_t i; 

	if (!do_debug_io || in_data)
		return;

	buffer[0] = '<';
	if (ssl) {
		en = 1;
		buffer[1] = 'e';
	}
	buffer[1 + en] = ' ';
	memcpy(buffer + 2 + en, linein, len);
	buffer[2 + en + len] = '\0';
	for (i = len + 1 + en; i > 0; i--) {
		if (buffer[i] < 32)
			buffer[i] = '?';
	}

	log_write(LOG_DEBUG, buffer);
}

void DEBUG_OUT(const char *s, const size_t l)
{
	char buffer[l + 4];
	int en = 0;
	const char *b, *c;
	
	if (!do_debug_io || in_data)
		return;

	buffer[0] = '>';
	if (ssl) {
		en = 1;
		buffer[1] = 'e';
	}
	buffer[1 + en] = ' ';

	b = s;
	while ( (c = strchr(b, '\r')) && (b < s + l) ) {
		memcpy(buffer + 2 + en, b, c - b);
		buffer[2 + c - b + en] = '\0';
		log_write(LOG_DEBUG, buffer);
		b = c + 2;
	}
}

#else

#define DEBUG_IN(l) {}
#define DEBUG_OUT(s, l) {}

#endif

/**
 * read characters from (network) input
 *
 * @param buffer buffer to put the data in
 * @param len maximum length of data to read (one char less is read, the last one is set to '\0')
 * @return -1 on error (errno is set), number of bytes read otherwise
 */
static size_t
readinput(char *buffer, const size_t len)
{
	size_t retval;
	fd_set rfds;
	struct timeval tv = {
		.tv_sec = timeout,
		.tv_usec = 0,
	};

	if (ssl) {
		retval = ssl_timeoutread(tv.tv_sec, buffer, len - 1);
	} else {
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);

		retval = select(1, &rfds, NULL, NULL, &tv);

		if (!retval) {
			dieerror(ETIMEDOUT);
		} else if (retval == (size_t) -1) {
			return retval;
		}
		retval = read(0, buffer, len - 1);
	}
	if (!retval) {
		dieerror(ECONNRESET);
	} else if (retval != (size_t) -1) {
		buffer[retval] = '\0';
	}
	return retval;
}

/**
 * read one line from the network
 *
 * @return  0 on success
 *         -1 on error (errno is set)
 *
 * does not return on timeout, programm will be cancelled
 */
int
net_read(void)
{
	size_t datain;
	size_t readoffset = 0;
	size_t i;
	char *p;

	if (linenlen) {
		char *c;

		memcpy(linein, lineinn, linenlen);
		linein[linenlen] = '\0';

		c = memchr(linein, '\n', linenlen);
		if (c) {
			/* First skip the input, then check for error.
			 * In case of input error we can still loop until
			 * end of input. */
			linelen = c - linein - 1;
			/* at this point the new linein is ready */

			linenlen = linein + linenlen - c - 1;
			if (linenlen) {
				/* copy back rest of the buffer back to lineinn */
				memcpy(lineinn, c + 1, linenlen);
			}
			
			if (*(c - 1) != '\r') {
				errno = EINVAL;
				return -1;
			}
			*(c - 1) = '\0';

			DEBUG_IN(linelen);

			return 0;
		} else {
			readoffset = linenlen;
			memcpy(linein, lineinn, linenlen);
			linenlen = 0;
		}
	}
readin:
	datain = readinput(linein + readoffset, sizeof(linein) - readoffset);
	/* now the first readoffset characters of linein are filled with the stuff from the last buffer (if any),
	 * the next datain characters are filled with the data just read, then there is a '\0' */

	if (datain == (size_t) -1)
		return -1;

	/* RfC 2821, section 2.3.7:
	 * "Conforming implementations MUST NOT recognize or generate any other
	 * character or character sequence [than <CRLF>] as a line terminator" */

	readoffset += datain;
	p = memchr(linein, '\r', readoffset);
	if (!p) {
		if (readoffset > sizeof(linein) - 2) {
		    readoffset = 0;
		    goto loop_long;
		} else {
			/* There was data, but not enough. Give it another chance */
			goto readin;
		}
	} else if (p == linein + sizeof(linein) - 1) {
		readoffset = 1;
		goto loop_long;
	} else if (!*(p + 1)) {
		/* There was data, but not enough. Give it another chance */
		goto readin;
	} else if (*(p + 1) != '\n') {
		errno = EINVAL;
		return -1;
	}

	linelen = p - linein;
	*p = '\0';

	i = readoffset - linelen - 2;
	if (i) {
		memcpy(lineinn + linenlen, p + 2, i);
		linenlen += i;
	}

	/* do this again here: if there is a broken client that
	 * handles '.' duplication in data phase wrong this allows
	 * smtp_data to get his '\n.\n' and throw him out. If he
	 * is broken once why not twice? */
	
	DEBUG_IN(linelen);

	return 0;
loop_long:
	/* if readoffset is set the last character in the previous buffer was '\r' */
	linenlen = 0;
	do {
		size_t j = readinput(linein, sizeof(linein));

		if (j == (size_t) -1)
			return -1;
		if (readoffset && (linein[0] == '\n')) {
			p = linein + 1;
			break;
		}
		p = linein;
		if ((linein[0] != '\r') && (linein[1] == '\n'))
			linein[1] = '\0';
		while (p && (*(p + 1) != '\n')) {
			if (p == linein + sizeof(linein) - 1) {
				readoffset = 1;
				goto loop_long;
			}
			/* catch "\r\r" */
			if (*p == '\r') {
				p++;
				j--;
			}
			p = memchr(p, '\r', j);
			j -= (p - linein);
		}
		readoffset = 0;
	} while (!p);
	linenlen = linein + datain - p - 2;
	memcpy(lineinn, p + 2, linenlen);
	errno = E2BIG;
	return -1;
}

/**
 * write one line to the network
 *
 * @param s line to be written (nothing else it written so it should contain CRLF)
 * @return 0 on success
 *         -1 on error (errno is set)
 *
 * -does not return on timeout, programm will be cancelled
 * -same as net_write but expects that line is <= 512 characters and includes CRLF
 */
inline int
netwrite(const char *s)
{
	return netnwrite(s, strlen(s));
}

/**
 * write one line to the network
 *
 * @param s line to be written (nothing else it written so it should contain CRLF)
 * @param l length of s
 * @return 0 on success
 *         -1 on error (errno is set)
 *
 * does not return on timeout, programm will be cancelled
 */
int
netnwrite(const char *s, const size_t l)
{
	fd_set wfds;
	struct timeval tv = {
		.tv_sec = timeout,
		.tv_usec = 0,
	};
	int retval;

	DEBUG_OUT(s, l);

	if (ssl) {
		if (ssl_timeoutwrite(tv.tv_sec, s, l) <= 0) {
			errno = EBADE;
			return -1;
		}
		return 0;
	}
	FD_ZERO(&wfds);
	FD_SET(socketd, &wfds);

	retval = select(socketd + 1, NULL, &wfds, NULL, &tv);

	if (retval == -1)
		return retval;
	else if (!retval)
		dieerror(ETIMEDOUT);

	if (write(socketd, s, l) < 0) {
		if (errno == EPIPE)
			dieerror(ECONNRESET);
		return -1;
	}
	return 0;
}

/**
 * write one line to the network, fold if needed
 *
 * @param s array of strings to send
 * @return 0 on success
 *         -1 on error (errno is set)
 *
 * does not return on timeout, programm will be cancelled
 *
 * \warning s[0] must be short enough to fit completely into the buffer
 * \warning every s[] must not have a sequence longer then 506 characters without a space (' ') in them
 */
int
net_writen(const char *const *s)
{
	unsigned int i;
	size_t len = 0;
	/* RfC 2821, section 4.5.3: reply line
	 *   The maximum total length of a reply line including the reply code
	 *   and the <CRLF> is 512 characters.  More information may be
	 *   conveyed through multiple-line replies. */
	char msg[512];

	for (i = 0; s[i]; i++) {
		size_t off = 0;
		size_t l = strlen(s[i]);

		if (len + l > sizeof(msg) - 2) {
			char c = msg[3];

			msg[3] = '-';
			msg[len++] = '\r';
			msg[len++] = '\n';
			/* ignore if this fails: if the last on succeeds this must be enough for the client */
			(void) netnwrite(msg, len + 2);
			len = 4;
			/* check if s[i] itself is too big */
			if (l + 6 > sizeof(msg)) {
				const char *sp = s[i], *nsp;

				while (l > off + sizeof(msg) - 6) {
					size_t m;

					nsp = strchr(s[i] + off, ' ');

					while (nsp - s[i] - off < sizeof(msg) - 6) {
						sp = nsp;
						nsp = strchr(sp + 1, ' ');
					}
					m = sp - s[i] - off;
					memcpy(msg + 4, s[i] + off, m);
					m += 4;
					msg[m++] = '\r';
					msg[m++] = '\n';
					netnwrite(msg, m);
					off += m - 6;
				}
			}
			msg[3] = c;
		}
		memcpy(msg + len, s[i] + off, l - off);
		len += l - off;
	}
	msg[len++] = '\r';
	msg[len++] = '\n';
	return netnwrite(msg, len);
}

/**
 * print unsigned long into a given buffer
 *
 * @param u number to convert
 * @param res pointer to memory where result is stored, should be ULSTRLEN bytes long
 */
void
ultostr(const unsigned long u, char *res)
{
	int j = 1;
	unsigned long v = u;

	while (v /= 10) {
		j++;
	}

	res[j] = '\0';
	v = u;
	do {
		res[--j] = '0' + v % 10;
		v /= 10;
	} while (j);
}

/**
 * read a given number of bytes from network as binary data (i.e. without any mangling)
 *
 * @param num number of bytes to read
 * @param buf buffer to store data (must have enough space for (num + 1) bytes)
 * @return number of bytes read, -1 on error
 */
size_t
net_readbin(size_t num, char *buf)
{
	size_t offs = 0;

	if (linenlen) {
		if (linenlen > num) {
			memcpy(buf, lineinn, num);
			memmove(lineinn, lineinn + num, linenlen - num);
			linenlen -= num;
			return 0;
		} else {
			memcpy(buf, lineinn, linenlen);
			num -= linenlen;
			offs = linenlen;
			linenlen = 0;
		}
	}
	while (num) {
		size_t r;

		r = readinput(buf + offs, num + 1);
		if (r == (size_t) -1)
			return -1;
		offs += r;
		num -= r;
	}
	return offs;
}

/**
 * read up to a given number of bytes from network but stop at the first CRLF
 *
 * @param num number of bytes to read, must be < 1002 so everything behind the CRLF can be copied back to lineinn
 * @param buf buffer to store data (must have enough space)
 * @return number of bytes read, -1 on error
 */
size_t
net_readline(size_t num, char *buf)
{
	size_t offs = 0;

	if (linenlen) {
		char *n = memchr(lineinn, '\n', linenlen);

		if (n) {
			size_t m = (n - lineinn);

			if (m < num)
				num = m;
		}
		/* now num is the number of bytes to copy from lineinn */
		if (linenlen > num) {
			memcpy(buf, lineinn, num);
			memmove(lineinn, lineinn + num, linenlen - num);
			linenlen -= num;
			return 0;
		} else {
			memcpy(buf, lineinn, linenlen);
			num -= linenlen;
			offs = linenlen;
			linenlen = 0;
		}
	}
	while (num) {
		size_t r;
		char *n;

		r = readinput(buf + offs, num);
		if (r == (size_t) -1)
			return -1;
		n = memchr(buf + offs, '\n', r);
		/* if there is a LF in the buffer copy everything behind it to lineinn */
		if (n) {
			size_t rest = buf + offs + r - n - 1;

			memcpy(lineinn, n + 1, rest);
			linenlen = rest;
			offs += r - rest;
			return offs;
		}
		offs += r;
		num -= r;
	}
	return offs;
}

/**
 * check if there is data ready to be read without blocking
 *
 * @return 0 if no data, 1 if data, -1 on error
 */
int
data_pending(void)
{
	if (linenlen) {
		return 1;
	} else if (ssl) {
		return SSL_pending(ssl);
	} else {
		fd_set rfds;
		struct timeval tv = {
			.tv_sec = 0,
			.tv_usec = 0,
		};
	
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
	
		return select(1, &rfds, NULL, NULL, &tv);
	}
}
