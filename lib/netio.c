#include <sys/select.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "netio.h"
#include "log.h"
#include "ssl_timeoutio.h"
#include "tls.h"

char linein[1002];			/* buffer for the line to read: max 1000 chars including CRLF,
					 * leading extra '.', closing '\0' */
unsigned int linelen;			/* length of the line */
static char lineinn[sizeof(linein)];	/* if more than one line was in linein the rest is stored here */
unsigned int linenlen;			/* length of the lineinn */

/**
 * readinput - read characters from (network) input
 *
 * @buffer: buffer to put the data in
 * @len: maximum length of data to read (one char less is read, the last one is set to '\0')
 *
 * returns: -1 on error (errno is set), number of bytes read otherwise
 */
int readinput(char *buffer, const unsigned int len)
{
	int retval;
	fd_set rfds;
	/* RfC 2821, section 4.5.3.2: "Timeouts"
	 * An SMTP server SHOULD have a timeout of at least 5 minutes while it
	 * is awaiting the next command from the sender. */
	struct timeval tv = {
		.tv_sec = 320,
		.tv_usec = 0,
	};

	if (ssl) {
		retval = ssl_timeoutread(tv.tv_sec, buffer, len - 1);
	} else {
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);

		retval = select(1, &rfds, NULL, NULL, &tv);

		if (!retval)
			dieerror(ETIMEDOUT);
		if (retval < 0)
			return retval;
		retval = read(0, buffer, len - 1);
	}
	if (retval > 0) {
		buffer[retval] = '\0';
	} else if (!retval) {
		dieerror(ECONNRESET);
	}
	return retval;
}

/**
 * net_read - read one line from the network
 *
 * returns: 0 on success
 *          -1 on error (errno is set)
 *
 *          does not return on timeout, programm will be cancelled
 */
int
net_read(void)
{
	int datain;
	unsigned int readoffset = 0;
	unsigned int i;
	char *p;

	if (linenlen) {
		char *c;

		memcpy(linein, lineinn, linenlen);
		linein[linenlen] = '\0';
		c = strchr(linein, '\n');
		if (c) {
			if (*(c - 1) != '\r') {
				errno = EINVAL;
				return -1;
			}
			*(c - 1) = '\0';
			linelen = c - linein - 1;
			/* at this point the new linein is ready */

			linenlen = linein + linenlen - c - 1;
			if (linenlen) {
				/* copy back rest of the buffer back to lineinn */
				memcpy(lineinn, c + 1, linenlen);
			}
			return 0;
		} else {
			readoffset = linenlen;
			memcpy(linein, lineinn, linenlen);
			linenlen = 0;
		}
		
	}
readin:
	datain = readinput(linein + readoffset, sizeof(linein) - readoffset);

	/* RfC 2821, section 2.3.7:
	 * "Conforming implementations MUST NOT recognize or generate any other
	 * character or character sequence [than <CRLF>] as a line terminator" */

	p = strchr(linein, '\r');
	if (!p) {
		readoffset += datain;
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
/*fprintf(stderr, "linein: %s\n", linein);
fprintf(stderr, "== offset: %i\n", p - linein);
dump("linein", linein, readoffset + datain);*/
		errno = EINVAL;
		return -1;
	}

	
	linelen = p - linein;
	*p = '\0';

	i = datain + readoffset - linelen - 2;
	if (i) {
		memcpy(lineinn + linenlen, p + 2, i);
		linenlen += i;
	}

	/* do this again here: if there is a broken client that
	 * handles '.' duplication in data phase wrong this allows
	 * smtp_data to get his '\n.\n' and throw him out. If he
	 * is broken once why not twice? */
	return 0;
loop_long:
	linenlen = 0;
	do {
		readinput(linein, sizeof(linein));
		if (readoffset && (linein[0] == '\n')) {
			p = linein + 1;
			break;
		}
		p = linein;
		if ((linein[0] != '\r') && (linein[1] == '\n'))
			linein[1] = 'x';
		while (p && (*(p+1) != '\n')) {
			if (p == linein + sizeof(linein) - 1) {
				readoffset = 1;
				goto loop_long;
			}
			p = strchr(p, '\r');
		}
		if (p)
			break;
		readoffset = 0;
	} while (1);
	linenlen = linein + datain - p - 2;
	memcpy(lineinn, p + 2, linenlen);
	errno = E2BIG;
	return -1;
}

/**
 * net_write - write one line from the network
 *
 * @s: line to be written (nothing else it written so it should contain <CRLF>)
 *
 * returns: 0 on success
 *          -1 on error (errno is set)
 *
 *          does not return on timeout, programm will be cancelled
 */
int
netwrite(const char *s)
{
	fd_set wfds;
	struct timeval tv = {
		.tv_sec = 120,
		.tv_usec = 0,
	};
	int retval;
	unsigned int l = strlen(s);

	if (ssl) {
		sleep(30);
		if (ssl_timeoutwrite(tv.tv_sec, s, l) <= 0) {
			errno = EBADE;
			return -1;
		}
		return 0;
	}
	FD_ZERO(&wfds);
	FD_SET(1, &wfds);

	retval = select(2, NULL, &wfds, NULL, &tv);

	if (retval == -1)
		return retval;
	else if (!retval)
		dieerror(ETIMEDOUT);

	if (write(1, s, l) < 0)
		return -1;
	return 0;
}

/**
 * net_writen - write one line from the network
 *
 * returns: 0 on success
 *          -1 on error (errno is set)
 *
 *          does not return on timeout, programm will be cancelled
 */
int
net_writen(const char *const *s)
{
	unsigned int i, len = 0;
	/* RfC 2821, section 4.5.3: reply line
	 *   The maximum total length of a reply line including the reply code
	 *   and the <CRLF> is 512 characters.  More information may be
	 *   conveyed through multiple-line replies. */
	char msg[511];

	for (i = 0; s[i]; i++) {
		unsigned int l = strlen(s[i]);

		/* silently ignore the case if s[i] itself is too big */
		if (len + l > sizeof(msg) - 1) {
			char c = msg[3];

			msg[3] = '-';
			memcpy(msg + len, "\r\n\0", 3);
			/* ignore if this fails: if the last on succeeds this must be enough for the client */
			net_write(msg);
			msg[3] = c;
			len = 4;
		}
		memcpy(msg + len, s[i], l);
		len += l;
	}
	memcpy(msg + len, "\r\n\0", 3);
	return netwrite(msg);
}

/**
 * ultostr - return a dynamically alloced buffer with the string represantation of an unsigned long
 *
 * @u: number to convert
 *
 * returns: pointer to buffer on success, "nomem" otherwise
 */
char *
ultostr(const unsigned long u)
{
	char *res;
	int j = 1;
	unsigned long v = u;

	while (v /= 10) {
		j++;
	}

	res = malloc(j + 1);
	if (!res)
		return "nomem";

	res[j] = '\0';
	v = u;
	do {
		res[--j] = '0' + v % 10;
		v /= 10;
	} while (j);
	return res;
}
