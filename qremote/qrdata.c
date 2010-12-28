/** \file qrdata.c
 \brief send message body to remote host

 This file contains the functions to send the message body to the remote host.
 Both DATA and BDAT modes are supported. In DATA mode the message will be recoded
 to quoted-printable if neccessary.
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include "netio.h"
#include "qremote.h"
#include "qrdata.h"
#include "version.h"
#include "mime.h"
#include "log.h"
#include "fmt.h"

const char *successmsg[] = {NULL, " accepted ", NULL, "message", "", "", "./Remote host said: ", NULL};
int ascii;			/* if message is plain ASCII or not */
const char *msgdata;		/* message will be mmaped here */
off_t msgsize;		/* size of the mmaped area */
static int lastlf = 1;		/* set if last byte sent was a LF */

/**
 * check if buffer has to be recoded for SMTP transfer
 *
 * @param buf buffer to scan
 * @param len length of buffer
 * @return logical or of: 1 if buffer has 8bit characters, 2 if buffer contains line longer 998 chars
 */
int
need_recode(const char *buf, off_t len)
{
	int res = 0;
	int llen = 0;

	while ((len-- > 0) && (res != 3)) {
		if (llen > 998) {
			res |= 2;
		}
		if (buf[len] <= 0) {
			res |= 1;
			llen++;
		} else if ((buf[len] == '\r') || (buf[len] == '\n')) {
			llen = 0;
			/* if buffer is too short we don't need to check for long lines */
			if ((len < 998) && (res != 0))
				return res;
		} else {
			llen++;
		}
	}

	return res;
}

/**
 * send message body, only fix broken line endings if present
 *
 * @param buf buffer to send
 * @param len length of data in buffer
 *
 * lastlf will be set if last 2 bytes sent were CRLF
 */
static void
send_plain(const char *buf, const off_t len)
{
	char sendbuf[1205];
	unsigned int idx = 0;
	size_t chunk = 0;	/* size of the chunk to copy into sendbuf */
	off_t off = 0;
	int llen = 0;		/* flag if start of line */

	if (!len)
		return;

	while (off < len) {
		while (idx + (off_t) chunk < sizeof(sendbuf) - 5) {
			if (off + (off_t) chunk == len) {
				break;
			}
			switch (buf[off + chunk]) {
				case '\r': {
						int last = (off + (off_t) ++chunk == len);

						llen = 0;
						if (!last && (buf[off + chunk] == '\n')) {
							chunk++;
						} else {
							memcpy(sendbuf + idx, buf + off, chunk);
							off += chunk;
							idx += chunk;
							sendbuf[idx++] = '\n';
							chunk = 0;
						}
						break;
					}
				case '\n': {
						/* bare '\n' */
						memcpy(sendbuf + idx, buf + off, chunk);
						off += chunk + 1;
						idx += chunk;
						sendbuf[idx++] = '\r';
						sendbuf[idx++] = '\n';
						chunk = 0;
						llen = 0;
						break;
					}
				case '.':
					if (!llen) {
						chunk++;
						memcpy(sendbuf + idx, buf + off, chunk);
						off += chunk;
						idx += chunk;
						sendbuf[idx++] = '.';
						chunk = 0;
						llen = 1;
						break;
					}
					/* fallthrough */
				default:
					chunk++;
					llen = 1;
			}
		}
		if (chunk) {
			memcpy(sendbuf + idx, buf + off, chunk);
			off += chunk;
			idx += chunk;
			chunk = 0;
		}

		if (len != off) {
			netnwrite(sendbuf, idx);
			lastlf = (sendbuf[idx - 1] == '\n');
			idx = 0;
		}
	}
	lastlf = (sendbuf[idx - 1] == '\n');
	netnwrite(sendbuf, idx);
}

static void
recodeheader(void)
{
	char buf[64 + heloname.len + strlen(VERSIONSTRING)];

	memcpy(buf, "Content-Transfer-Encoding: quoted-printable (recoded by: " VERSIONSTRING " at ",
			57 + strlen(VERSIONSTRING) + 4);
	memcpy(buf + 61 + strlen(VERSIONSTRING), heloname.s, heloname.len);
	buf[sizeof(buf) - 3] = ')';
	buf[sizeof(buf) - 2] = '\r';
	buf[sizeof(buf) - 1] = '\n';
	netnwrite(buf, sizeof(buf));
}

/**
 * fold one long header line
 *
 * @param buf beginning of line
 * @param len length of line without CR, LF or CRLF
 */
static off_t
wrap_line(const char *buf, off_t len)
{
	off_t off = len;
	off_t pos = 0;
	char sendbuf[1048];	/* long enough for 2 lines to fit in */
	size_t bo = 0;	/* offset in sendbuf */

	while (off >= 970) {
		off_t partoff = 800;

		while (partoff && (buf[pos + partoff] != ' '))
			partoff--;

		/* make sure that the parts are not too short */
		if (partoff < 50) {
			/* too short: look if we can find a longer part */
			partoff = 800;
			while ((partoff < 970) && (buf[pos + partoff] != ' '))
				partoff++;
			if (partoff >= 970)
				partoff = 800;
		}
		if (partoff + bo >= sizeof(sendbuf) - 4) {
			netnwrite(sendbuf, bo);
			bo = 0;
		}
		/* add the whitespace at the beginning of this line if this is not the first */
		if (pos)
			sendbuf[bo++] = ' ';
		partoff++;	/* the space must stay at the end of the line *
				 * all whitespace at the beginning of the new line
				 * will be ignored */
		memcpy(sendbuf + bo, buf + pos, partoff);
		bo += partoff;
		memcpy(sendbuf + bo, "\r\n", 2);
		bo += 2;
		pos += partoff;
		off -= partoff;
	}
	sendbuf[bo++] = ' ';
	if (off + bo >= sizeof(sendbuf) - 2) {
		/* The end of the line will be send by the calling function.
		 * Only make sure the whitespace at the beginning of the new
		 * line is there */
		netnwrite(sendbuf, bo);
		return pos;
	}
	memcpy(sendbuf + bo, buf + pos, off);
	bo += off;
	memcpy(sendbuf + bo, "\r\n", 2);
	netnwrite(sendbuf, bo + 2);
	return len;
}

/**
 * fold long lines in header
 *
 * @param buf buffer to send
 * @param len length of buffer
 */
static void
wrap_header(const char *buf, const off_t len)
{
	off_t pos = 0;	/* position of what is already sent */
	off_t off = 0;	/* start of current line relative to pos */
	off_t ll = 0;	/* length of current line */

	if (!(need_recode(buf, len) & 2)) {
		send_plain(buf, len);
		return;
	}

	while (pos + off + ll < len) {
		int l = 0;	/* length of CR, LF or CRLF sequence at end of line */

		if (buf[pos + off + ll] == '\r') {
			l++;
		}
		if ((pos + off + ll + l < len) && (buf[pos + off + ll + l] == '\n')) {
			l++;
		}
		if (!l) {
			ll++;
			continue;
		}
		/* found a line. Check if it's too long */
		if (ll >= 999) {
			off_t po;

			send_plain(buf + pos, off);
			pos += off;
			off = 0;
			po = wrap_line(buf + pos, ll);
			pos += po;
			/* if wrap_line() has not send the entire line we can skip over
                         * the last part, we now know it's short enough */
			if (po != ll) {
				ll = ll - po;
			} else {
				ll = 0;
				pos += l;
			}
		} else {
			off += ll + l;
			ll = 0;
		}
	}
	if (ll < 999) {
		off += ll;
		send_plain(buf + pos, off);
	} else {
		off_t po;

		send_plain(buf + pos, off);
		pos += off;
		po = wrap_line(buf + pos, ll);
		pos += po;
		/* if wrap_line() has not send the entire line we can skip over
			* the last part, we now know it's short enough */
		if (po != ll) {
			ll = ll - po;
		} else {
			ll = 0;
		}
		send_plain(buf + pos, off + ll);
	}
}

/**
 * scan and recode header: fix Content-Transfer-Encoding, check for boundary
 *
 * @param buf buffer to scan
 * @param len length of buffer
 * @param boundary if this is a multipart message a pointer to the boundary-string is stored here
 * @param multipart will be set to 1 if this is a multipart message
 * @return offset of end of header
 *
 * \warning boundary will not be 0-terminated! Use boundary->len!
 */
static off_t
qp_header(const char *buf, const off_t len, cstring *boundary, int *multipart)
{
	off_t off, header = 0;
	cstring cenc, ctype;

	STREMPTY(cenc);
	STREMPTY(ctype);
/* scan header */

	/* check if this is an empty header */
	if (buf[0] == '\r') {
		header = ((len > 1) && (buf[1] == '\n')) ? 2 : 1;
	} else if (buf[0] == '\n') {
		header = 1;
	}
	off = header;

	/* first: find the newline between header and body */
	while (!header && (off < len)) {
		switch (buf[off]) {
			case '\r':	off++;
					if ((off < len) && (buf[off] == '\n'))
						off++;
					if (off == len)
						break;
					if ((buf[off] == '\r') || (buf[off] == '\n')) {
						header = off;
					}
					break;
			case '\n':	off++;
					if (off == len)
						break;
					if ((buf[off] == '\r') || (buf[off] == '\n')) {
						header = off;
					}
					break;
			case 'c':
			case 'C':	{
						off_t rest = len - off;

						if ((rest >= 12) && !strncasecmp(buf + off + 1, "ontent-Type:", 11)) {
							const char *cr = buf + off;

							ctype.len = getfieldlen(cr, len - off);
							if (ctype.len) {
								ctype.s = cr;
								off += ctype.len - 2;
							}
							break;
						} else if ((rest >= 25) &&
								!strncasecmp(buf + off + 1, "ontent-Transfer-Encoding:", 25)) {
							const char *cr = buf + off;

							cenc.len = getfieldlen(cr, len - off);
							if (cenc.len) {
								cenc.s = cr;
								off += cenc.len - 2;
							}
							break;
						}
						/* fallthrough */
					}
			default:	off++;
					while ((off < len) && (buf[off] != '\r') && (buf[off] != '\n')) {
						off++;
					}
		}
	}
	if (!header || (need_recode(buf, header) & 1)) {
		/* no empty line found: treat whole message as header. But this means we have
		 * 8bit characters in header which is a bug in the client that we can't handle */
		write(1, "D5.6.3 message contains unencoded 8bit data in message header\n", 63);
		exit(0);
	}

	if ((*multipart = is_multipart(&ctype, boundary)) > 0) {
		/* content is implicitely 7bit if no declaration is present */
		if (cenc.len) {
			wrap_header(buf, cenc.s - buf);
			wrap_header(cenc.s + cenc.len, buf + header - cenc.s - cenc.len);
		} else {
			wrap_header(buf, header);
		}
	} else if (*multipart < 0) {
		write(1, "D5.6.3 syntax error in Content-Type message header\n", 52);
		exit(0);
	} else {
		if (cenc.len) {
			wrap_header(buf, cenc.s - buf);
			recodeheader();
			wrap_header(cenc.s + cenc.len, buf + header - cenc.s - cenc.len);
		} else {
			recodeheader();
			wrap_header(buf, header);
		}
	}
	return header;
}

/**
 * recode buffer to quoted-printable and send it to remote host
 *
 * @param buf data to send
 * @param len length of buffer
 */
static void
recode_qp(const char *buf, off_t len)
{
	unsigned int idx = 0;
	char sendbuf[1280];
	size_t chunk = 0;	/* size of the chunk to copy into sendbuf */
	off_t off = 0;
	int llen = 0;		/* length of this line, needed for qp line break */

	while (off < len) {
		while (idx + (off_t) chunk < sizeof(sendbuf) - 11) {
			if (off + (off_t) chunk == len) {
				break;
			}

			if (buf[off + chunk] == '\r') {
				chunk++;
				llen = 0;
				if (buf[off + chunk] == '\n') {
					chunk++;
				} else {
					memcpy(sendbuf + idx, buf + off, chunk);
					off += chunk;
					idx += chunk;
					sendbuf[idx++] = '\n';
					chunk = 0;
				}
				continue;
			} else if (buf[off + chunk] == '\n') {
				memcpy(sendbuf + idx, buf + off, chunk);
				off += chunk + 1;
				idx += chunk;
				chunk = 0;
				sendbuf[idx++] = '\r';
				sendbuf[idx++] = '\n';
				llen = 0;
				continue;
			}

			/* add soft line break to make sure encoded line length < 80 */
			if (llen > 72) {
				chunk++;
				memcpy(sendbuf + idx, buf + off, chunk);
				off += chunk;
				idx += chunk;
				chunk = 0;
				/* recode last character if it was whitespace */
				if (sendbuf[idx - 1] == '\t') {
					sendbuf[idx - 1] = '=';
					sendbuf[idx++] = '0';
					sendbuf[idx++] = '9';
				} else if (sendbuf[idx - 1] == ' ') {
					sendbuf[idx - 1] = '=';
					sendbuf[idx++] = '2';
					sendbuf[idx++] = '0';
				}
				sendbuf[idx++] = '=';
				sendbuf[idx++] = '\r';
				sendbuf[idx++] = '\n';
				llen = 0;
			}

			if (!llen && (buf[off + chunk] == '.')){
				chunk++;
				memcpy(sendbuf + idx, buf + off, chunk);
				off += chunk;
				idx += chunk;
				sendbuf[idx++] = '.';
				chunk = 0;
			} else if ((buf[off + chunk] == '\t') || (buf[off + chunk] == ' ')) {
				/* recode whitespace if a linebreak follows */
				if ((off + (off_t) chunk < len) &&
						((buf[off + chunk + 1] == '\r') || (buf[off + chunk + 1] == '\n'))) {
					memcpy(sendbuf + idx, buf + off, chunk);
					off += chunk;
					idx += chunk;
					sendbuf[idx++] = '=';
					if (buf[off] == '\t') {
						sendbuf[idx++] = '0';
						sendbuf[idx++] = '9';
					} else {
						sendbuf[idx++] = '2';
						sendbuf[idx++] = '0';
					}
					sendbuf[idx++] = '\r';
					sendbuf[idx++] = '\n';
					if (buf[++off] == '\r')
						off++;
					if ((off < len) && (buf[off] == '\n'))
						off++;
					llen = 0;
					chunk = 0;
				} else {
					chunk++;
					llen++;
				}
			} else if ((buf[off + chunk] < 32) || (buf[off + chunk] == '=') ||
							 (buf[off + chunk] > 126)) {
				const char hexchars[] = "0123456789ABCDEF";

				/* recode non-printable and non-ascii characters */
				memcpy(sendbuf + idx, buf + off, chunk);
				off += chunk;
				idx += chunk;
				chunk = 0;
				sendbuf[idx++] = '=';
				sendbuf[idx++] = hexchars[(buf[off] >> 4) & 0x0f];
				sendbuf[idx++] = hexchars[buf[off] & 0xf];
				llen +=3;
				off++;
			} else {
				llen++;
				chunk++;
			}
		}
		if (chunk) {
			memcpy(sendbuf + idx, buf + off, chunk);
			off += chunk;
			idx += chunk;
			chunk = 0;
		}

		if (len != off) {
			netnwrite(sendbuf, idx);
			lastlf = (sendbuf[idx - 1] == '\n');
			idx = 0;
		}
	}
	lastlf = (sendbuf[idx - 1] == '\n');
	netnwrite(sendbuf, idx);
}

/**
 * skip transport padding after boundaries (trailing whitespace and [CR]LF)
 *
 * @param buf buffer to encode
 * @param len length of buffer
 * @return number of bytes skipped
 */
static off_t
skip_tpad(const char *buf, const off_t len)
{
	off_t off = 0;

	while ((off < len) && ((buf[off] == ' ') || (buf[off] == '\t')))
		off++;
	if ((off < len) && (buf[off] == '\r'))
		off++;
	if ((off < len) && (buf[off] == '\n'))
		off++;
	return off;
}

/**
 * send message body, do quoted-printable recoding where needed
 *
 * @param buf buffer to encode
 * @param len length of buffer
 */
static void
send_qp(const char *buf, const off_t len)
{
	off_t off = 0;
	cstring boundary;
	int multipart;		/* set to one if this is a multipart message */

	off = qp_header(buf, len, &boundary, &multipart);

	if (!multipart) {
		recode_qp(buf + off, len - off);
	} else {
		off_t nextoff = find_boundary(buf + off, len - off, &boundary);
		int nr;
		int islast = 0;	/* set to one if MIME end boundary was found */

		if (!nextoff) {
			/* huh? message declared as multipart, but without any boundary? */
			/* add boundary */
			netnwrite("\r\n--", 4);
			netnwrite(boundary.s, boundary.len);
			netnwrite("\r\n", 2);
			/* add Content-Transfer-Encoding header and extra newline */
			recodeheader();
			netnwrite("\r\n", 2);
			/* recode body */
			recode_qp(buf + off, len - off);
			/* add end boundary */
			netnwrite("\r\n--", 4);
			netnwrite(boundary.s, boundary.len);
			netnwrite("--\r\n", 4);
			lastlf = 1;
			return;
		}

		/* check and send or discard MIME preamble */
		if ( (nr = need_recode(buf + off, nextoff)) ) {
			log_write(LOG_ERR, "discarding invalid MIME preamble");
			netnwrite("\r\ninvalid MIME preamble was dicarded.\r\n\r\n--", 43);
			netnwrite(boundary.s, boundary.len);
			off += nextoff;
		} else {
			send_plain(buf + off, nextoff);
			off += nextoff;
		}

		if (buf[off] == '-') {
			/* wow: end-boundary as first boundary. What next? Flying cows? */

			/* first: add normal boundary to make this a more or less usefull MIME message, then add an end boundary */
			netnwrite("\r\n\r\n--", 6);
			netnwrite(boundary.s, boundary.len);
			netnwrite("--", 2);
			islast = 1;
			off += 2;
		}

		off += skip_tpad(buf + off, len - off);
		netnwrite("\r\n", 2);

		while ((off < len) && !islast && (nextoff = find_boundary(buf + off, len - off, &boundary))) {
			off_t partlen = nextoff - boundary.len - 2;

			nr = need_recode(buf + off, partlen);
			if ((!(smtpext & 0x008) && (nr & 1)) || (nr & 2)) {
				send_qp(buf + off, partlen);
			} else {
				send_plain(buf + off, partlen);
			}
			netnwrite("--", 2);
			netnwrite(boundary.s, boundary.len);
			off += nextoff;
			if (buf[off] == '-') {
				/* this is end boundary */
				netnwrite("--", 2);
				off += 2;
				islast = 1;
			}
			off += skip_tpad(buf + off, len - off);

			if ((off == len) && !islast) {
				netnwrite("--\r\n", 4);
				lastlf = 1;
				return;
			}
			netnwrite("\r\n", 2);
			if (off == len)
				return;
		}

		/* Look if we have seen the final MIME boundary yet. If not, add it. */
		if (!islast) {
			netnwrite("\r\n--", 4);
			netnwrite(boundary.s, boundary.len);
			netnwrite("--\r\n", 4);
		}

		/* All normal MIME parts are processed now, what follow is the epilogue.
		 * Check if it needs recode. If it does, it is broken and can simply be
		 * discarded */
		if (need_recode(buf + off, len - off)) {
			log_write(LOG_ERR, "discarding invalid MIME epilogue");
			netnwrite("\r\ninvalid MIME epilogue has been discarded.\r\n", 45);
			lastlf = 1;
		} else {
			send_plain(buf + off, len - off);
		}
	}
}

void
send_data(void)
{
	int num;

	successmsg[2] = "";
	netwrite("DATA\r\n");
	if ( (num = netget()) != 354) {
		write(1, num >= 500 ? "D5" : "Z4", 2);
		write(1, ".3.0 remote host rejected DATA command: ", 40);
		write(1, linein + 4, linelen - 3);
		quit();
	}
#ifdef DEBUG_IO
	in_data = 1;
#endif

	if ((!(smtpext & 0x008) && (ascii & 1)) || (ascii & 2)) {
		successmsg[2] = "(qp recoded) ";
		send_qp(msgdata, msgsize);
	} else {
		send_plain(msgdata, msgsize);
	}
	if (lastlf) {
		netnwrite(".\r\n", 3);
	} else {
		netnwrite("\r\n.\r\n", 5);
	}

#ifdef DEBUG_IO
	in_data = 0;
#endif
	checkreply("KZD", successmsg, 1);
}

#ifdef CHUNKING
void
send_bdat(void)
{
	off_t off = 0;		/* offset in incoming message data */
	char *chunkbuf;
	size_t lenlen;			/* "reserved" length for "BDAT <len> (LAST)?" */
	int i;

	chunkbuf = mmap(NULL, chunksize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

	if (chunkbuf == MAP_FAILED) {
		log_write(LOG_WARNING, "cannot mmap() buffer for chunked transfer, fallback to normal transfer\n");
		send_data();
	}

	successmsg[2] = "chunked ";
	/* calculate length needed to send out the "BDAT <len>" stuff */
	lenlen = 0;
	i = chunksize;
	while (i) {
		lenlen++;
		i /= 10;
	}
	lenlen += 12; /* "BDAT " + " LAST" + CRLF */

#ifdef DEBUG_IO
	in_data = 1;
#endif
	while (off < msgsize) {
		size_t len = lenlen;	/* currently used space in chunkbuf */
		size_t cpoff = off;	/* offset the current line starts at */
		size_t linel = 0;	/* length of the currently parsed line */
		unsigned long hl;	/* length of header */

		while ((off < msgsize) && (len + linel < chunksize - 1)) {
			if (msgdata[off] == '\n') {
				if (!linel) {
					/* two linebreaks after each other. We
					 * need to insert CR here. We assume
					 * that normally there are not much
					 * empty lines after each other so the
					 * LF will be copied when the
					 * complete line is sent. */
					chunkbuf[len++] = '\r';
					linel++;
				} else if (linel && msgdata[off - 1] != '\r') {
					memcpy(chunkbuf + len, msgdata + cpoff, linel);
					len += linel++;
					chunkbuf[len++] = '\r';
					chunkbuf[len++] = '\n';
					cpoff += linel;
					linel = 0;
				} else {
					linel++;
				}
			} else {
				linel++;
			}
			off++;
		}
		/* this buffer is full. Put header in front, flush it out and start again */
		if (linel) {
			/* first copy remaining part of input buffer to output buffer */
			memcpy(chunkbuf + len, msgdata + cpoff, linel);
			len += linel;
			/* optimize: never send a CR at end of chunk. This is inefficient as
			 * hell for both RX and TX. We always send LF behind it so we don't
			 * have to remember the state of the CRLF encoding between chunks. */
			if (msgdata[off - 1] == '\r') {
				/* CR means LF will follow. If the LF is not in input
				 * stream we will insert one. Garbage in, Garbage out.
				 * This is 8BITMIME and not BINARYMIME. */
				chunkbuf[len++] = '\n';
				if ((off < msgsize - 1) && (msgdata[off] == '\n')) {
					off++;
				} else {
					log_write(LOG_WARNING, "found bare CR in message\n");
				}
			}
		}

		/* write header */
		i = 7;	/* "BDAT " + CRLF */
		hl = len - lenlen;
		/* just to be sure: len == 0 */
		if (!hl) {
			i++;
		} else {
			while (hl) {
				i++;
				hl /= 10;
			}
		}

		if (off == msgsize) {
			/* " LAST" */
			i += 5;
		}
		hl = lenlen - i;
		memcpy(chunkbuf + hl, "BDAT ", 5);
		ultostr(len - lenlen, chunkbuf + hl + 5);
		if (off == msgsize) {
			memcpy(chunkbuf + lenlen - 7, " LAST\r\n", 7);
		} else {
			chunkbuf[lenlen - 2] = '\r';
			chunkbuf[lenlen - 1] = '\n';
		}
		netnwrite(chunkbuf + hl, len - hl);
		if (off != msgsize)
			if (checkreply(" ZD", NULL, 0) != 250) {
				munmap(chunkbuf, chunksize);
				quit();
			}
	}
#ifdef DEBUG_IO
	in_data = 0;
#endif
	munmap(chunkbuf, chunksize);
	checkreply("KZD", successmsg, 1);
}
#endif
