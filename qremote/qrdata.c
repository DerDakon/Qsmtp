#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "netio.h"
#include "qremote.h"
#include "qrdata.h"
#include "version.h"
#include "mime.h"

const char *successmsg[] = {NULL, " accepted ", NULL, "message", "", "./Remote_host_said: ", NULL};
int ascii;			/* if message is plain ASCII or not */
const char *msgdata;		/* message will be mmaped here */
q_off_t msgsize;		/* size of the mmaped area */
static int lastlf = 1;		/* set if last byte sent was a LF */

static int multipart;		/* set to one if this is a multipart message */

static void __attribute__ ((noreturn))
die_8bitheader(void)
{
	write(1, "D5.6.3 message contains unencoded 8bit data in message header\n", 63);
	exit(0);
}

/**
 * need_recode - check if buffer has to be recoded for SMTP transfer
 *
 * @buf: buffer to scan
 * @len: length of buffer
 *
 * returns: logical or of: 1 if buffer has 8bit characters, 2 if buffer contains line longer 998 chars
 */
int
need_recode(const char *buf, q_off_t len)
{
	int res = 0;
	int llen = 0;

	/* if buffer is too short we don't need to check for long lines */
	if (len >= 998) {
		while (len-- > 0) {
			if (buf[len] <= 0) {
				res |= 1;
				llen++;
			} else if ((buf[len] == '\r') || (buf[len] == '\n')) {
				llen = 0;
			} else {
				llen++;
			}
			if (llen > 998) {
				if (res) {
					return 3;
				} else {
					res |= 2;
					break;
				}
			}
		}
	}
	/* only scan for 8bit characters now */
	while (len-- > 0) {
		if (buf[len] <= 0) {
			res |= 1;
			break;
		}
	}
	return res;
}

/**
 * send_plain - send message body, only fix broken line endings if present
 *
 * @buf: buffer to send
 * @len: length of data in buffer
 *
 * lastlf will be set if last 2 bytes sent were CRLF
 */
static void
send_plain(const char *buf, const q_off_t len)
{
	char sendbuf[1205];
	unsigned int idx = 0;
	size_t chunk = 0;	/* size of the chunk to copy into sendbuf */
	q_off_t off = 0;
	int llen = 0;		/* length of line */

	while (off < len) {
		while (idx + (q_off_t) chunk < sizeof(sendbuf) - 5) {
			if (off + (q_off_t) chunk == len) {
				break;
			}
			switch (buf[off + chunk]) {
				case '\r':	{
							int last = (off + (q_off_t) ++chunk == len);
		
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
				case '\n':	{
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
				case '.':	if (!llen) {
							chunk++;
							memcpy(sendbuf + idx, buf + off, chunk);
							off += chunk;
							idx += chunk;
							sendbuf[idx++] = '.';
							chunk = 0;
							break;
						}
						/* fallthrough */
				default:	chunk++;
						llen++;
			}
			if (llen > 998) {
				/* if we knew this before we could have used quoted-printable... */
				write(1, "D5.6.3 message has too long line\n", 34);
				_exit(0);
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
 * qp_header - scan and recode header: fix Content-Transfer-Encoding, check for boundary
 *
 * @boundary: if this is a multipart message a pointer to the boundary-string is stored here
 *
 * returns: offset of end of header
 *
 * Warning: boundary will not be 0-terminated! Use boundary->len!
 */
static q_off_t
qp_header(string *boundary)
{
	const char *recodeheader[] = {"Content-Transfer-Encoding: quoted-printable (recoded by: ", VERSIONSTRING,
					" at ", heloname.s, ")", NULL};
	q_off_t off = 0, header = 0;
	cstring cenc, ctype;

	STREMPTY(cenc);
	STREMPTY(ctype);
/* scan header */
	/* first: find the newline between header and body */
	while (off < msgsize) {
		if (msgdata[off] == '\r') {
			off++;
			if ((off < msgsize) && (msgdata[off] == '\n'))
				off++;
			if (off == msgsize)
				break;
			if ((msgdata[off] == '\r') || (msgdata[off] == '\n')) {
				header = off;
				break;
			}
		} else if (msgdata[off] == '\n') {
			off++;
			if (off == msgsize)
				break;
			if ((msgdata[off] == '\r') || (msgdata[off] == '\n')) {
				header = off;
				break;
			}
		}

		if ((msgdata[off] == 'c') || (msgdata[off] == 'C')) {
			size_t rest = (size_t) (msgsize - off);

			if ((rest >= 12) && !strncasecmp(msgdata + off + 1, "ontent-Type:", 11)) {
				const char *cr = msgdata + off;

				ctype.len = getfieldlen(cr, msgsize - off);
				if (ctype.len) {
					ctype.s = cr;
					off += ctype.len - 2;
					continue;
				}
			} else if ((rest >= 25) &&
					!strncasecmp(msgdata + off + 1, "ontent-Transfer-Encoding:", 25)) {
				const char *cr = msgdata + off;

				cenc.len = getfieldlen(cr, msgsize - off);
				if (cenc.len) {
					cenc.s = cr;
					off += cenc.len - 2;
					continue;
				}
			} else {
				off++;
			}
		} else {
			off++;
		}
	}
	if (!header) {
		/* no empty line found: treat whole message as header. But this means we have
		 * 8bit characters in header which is a bug in the client that we can't handle */
		die_8bitheader();
	}

	/* We now know how long the header is. Check it if there are unencoded 8bit characters */
	off = header;

	if (need_recode(msgdata, header) & 1)
		die_8bitheader();

	if ( (multipart = is_multipart(&ctype, boundary)) ) {
#warning FIXME: change Content-Transfer-Encoding to 7bit/quoted-printable in multipart messages
/*		if (cenc.len) {
			netnwrite(msgdata, cenc.s - msgdata);
			netnwrite("Content-Transfer-Encoding: 7bit\r\n", 33);
			netnwrite(cenc.s + cenc.len, msgdata + header - cenc.s - cenc.len);
		} else {
			netnwrite(msgdata, header);
			netnwrite("Content-Transfer-Encoding: 7bit\r\n", 33);
		}*/
	} else {
		if (cenc.len) {
			send_plain(msgdata, cenc.s - msgdata);
			net_writen(recodeheader);
			send_plain(cenc.s + cenc.len, msgdata + header - cenc.s - cenc.len);
		} else {
			send_plain(msgdata, header);
			net_writen(recodeheader);
		}
	}
	return header;
}

/**
 * recode_qp - recode buffer to quoted-printable and send it to remote host
 *
 * @buf: data to send
 * @len: length of buffer
 */
static void
recode_qp(const char *buf, q_off_t len)
{
	unsigned int idx = 0;
	char sendbuf[1280];
	size_t chunk = 0;	/* size of the chunk to copy into sendbuf */
	q_off_t off = 0;
	int llen = 0;		/* length of this line, needed for qp line break */

	while (off < len) {
		while (idx + (q_off_t) chunk < sizeof(sendbuf) - 11) {
			if (off + (q_off_t) chunk == len) {
				break;
			}

			if (buf[off + chunk] == '\r') {
				chunk++;
				llen = 0;
				if (buf[off + chunk] == '\n') {
					chunk++;
				} else {
					chunk++;
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
				if ((off + (q_off_t) chunk < len) &&
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
 * send_qp - send message body, do quoted-printable recoding where needed
 */
static void
send_qp(void)
{
	q_off_t off = 0;
	string boundary;

	off = qp_header(&boundary);
	
	if (multipart) {
#warning FIXME: add proper quoted-printable recoding here
		write(1, "Z4.6.3 message has 8 Bit characters but next server does not accept 8BITMIME", 77);
		exit(0);
	} else {
		recode_qp(msgdata + off, msgsize - off);
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

#ifdef USE_QP_RECODE
	if (!(smtpext & 0x008) && ascii) {
		successmsg[2] = "(qp recoded) ";
		send_qp();
	} else {
#else
	{
#endif
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
	return;
}

void
send_bdat(void)
{
	char chunklen[6];
	const char *netmsg[] = {"BDAT ", NULL, NULL, NULL};
	q_off_t off = 0;

	successmsg[2] = "chunked ";

#define CHUNKSIZE 15000
	netmsg[1] = "15000";
	while (msgsize - off > CHUNKSIZE) {
		net_writen(netmsg);
#ifdef DEBUG_IO
		in_data = 1;
#endif
		netnwrite(msgdata + off, CHUNKSIZE);
#ifdef DEBUG_IO
		in_data = 0;
#endif
		if (checkreply(" ZD", NULL, 0) != 250)
			quit();
		off += CHUNKSIZE;
	}
	ultostr((unsigned long) (msgsize - off), chunklen);
	netmsg[1] = chunklen;
	netmsg[2] = " LAST";
	net_writen(netmsg);
#ifdef DEBUG_IO
	in_data = 1;
#endif
	netnwrite(msgdata + off, msgsize - off);
#ifdef DEBUG_IO
	in_data = 0;
#endif
	checkreply("KZD", successmsg, 1);
}
