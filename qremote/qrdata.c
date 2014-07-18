/** \file qrdata.c
 \brief send message body to remote host

 This file contains the functions to send the message body to the remote host.
 Both DATA and BDAT modes are supported. In DATA mode the message will be recoded
 to quoted-printable if neccessary.
 */

#include <qremote/qrdata.h>

#include <fmt.h>
#include <log.h>
#include <netio.h>
#include <qremote/client.h>
#include <qremote/mime.h>
#include <qremote/qremote.h>
#include <version.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

const char *successmsg[] = {NULL, " accepted ", NULL, "message", "", "", "./Remote host said: ", NULL};
const char *msgdata;		/* message will be mmaped here */
off_t msgsize;		/* size of the mmaped area */
static int lastlf = 1;		/* set if last byte sent was a LF */

/**
 * check if buffer has to be recoded for SMTP transfer
 *
 * @param buf buffer to scan
 * @param len length of buffer
 * @return logical or of:
 *   - 1: buffer has 8bit characters
 *   - 2: buffer contains line longer 998 chars
 *   - 4: header contains line longer 998 chars
 */
unsigned int
need_recode(const char *buf, off_t len)
{
	int res = 0;
	int llen = 0;
	int in_header = 1;
	off_t pos = 0;

	while ((pos < len) && (res != 3)) {
		if (llen > 998) {
			if (in_header)
				res |= 4;
			else
				res |= 2;
		}
		if (buf[pos] <= 0) {
			res |= 1;
			llen++;
		} else if ((buf[pos] == '\r') || (buf[pos] == '\n')) {
			if ((buf[pos] == '\r') && (pos < len - 1) && (buf[pos + 1] == '\n'))
				pos++;
			if (llen == 0)
				in_header = 0;
			llen = 0;
			/* if buffer is too short we don't need to check for long lines */
			if ((len - pos < 998) && (res & 1))
				return res;
		} else {
			llen++;
		}
		pos++;
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

	assert(len >= 0);

	if (len <= 0)
		return;

	while (off < len) {
		while (idx + chunk < sizeof(sendbuf) - 5) {
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
			case '\n':
				/* bare '\n' */
				memcpy(sendbuf + idx, buf + off, chunk);
				off += chunk + 1;
				idx += chunk;
				sendbuf[idx++] = '\r';
				sendbuf[idx++] = '\n';
				chunk = 0;
				llen = 0;
				break;
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
	static const char recodedstr[] = "Content-Transfer-Encoding: "
			"quoted-printable\r\n"
			"X-MIME-Autoconverted: from 8bit to quoted-printable by Qremote " QSMTPVERSION " at ";
	char buf[heloname.len + 2 + strlen(recodedstr)];

	memcpy(buf, recodedstr, strlen(recodedstr));
	memcpy(buf + strlen(recodedstr), heloname.s, heloname.len);
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
			off_t lateoff = 800;
			while ((lateoff < 970) && (buf[pos + lateoff] != ' '))
				lateoff++;
			if (lateoff < 970)
				partoff = lateoff;
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

static off_t
send_wrapped(const char *buf, off_t pos, off_t *off, off_t *ll, const unsigned int l)
{
	if (*ll < 999) {
		*off += *ll + l;
		*ll = 0;
	} else {
		off_t po;

		send_plain(buf + pos, *off);
		pos += *off;
		*off = 0;
		po = wrap_line(buf + pos, *ll);
		pos += po;
		/* if wrap_line() has not send the entire line we can skip over
		 * the last part, we now know it's short enough */
		if (po != *ll) {
			*ll -= po;
		} else {
			*ll = 0;
			pos += l;
		}
	}

	return pos;
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

	if (!(need_recode(buf, len) & 4)) {
		send_plain(buf, len);
		return;
	}

	while (pos + off + ll < len) {
		unsigned int l = 0;	/* length of CR, LF or CRLF sequence at end of line */

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
		pos = send_wrapped(buf, pos, &off, &ll, l);
	}

	pos = send_wrapped(buf, pos, &off, &ll, 0);
	send_plain(buf + pos, off + ll);
}

/**
 * scan and recode header: fix Content-Transfer-Encoding, check for boundary
 *
 * @param buf buffer to scan
 * @param len length of buffer
 * @param boundary if this is a multipart message a pointer to the boundary-string is stored here
 * @param multipart will be set to 1 if this is a multipart message
 * @param body_recode if the body needs recoding (i.e. the CTE-header needs to be set)
 * @return offset of end of header
 *
 * \warning boundary will not be 0-terminated! Use boundary->len!
 */
static off_t
qp_header(const char *buf, const off_t len, cstring *boundary, int *multipart, const unsigned int body_recode)
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
		case '\r':
			off++;
			if ((off < len) && (buf[off] == '\n'))
				off++;
			if (off == len)
				break;
			if ((buf[off] == '\r') || (buf[off] == '\n')) {
				header = off;
			}
			break;
		case '\n':
			off++;
			if (off == len)
				break;
			if ((buf[off] == '\r') || (buf[off] == '\n')) {
				header = off;
			}
			break;
		case 'c':
		case 'C':
			{
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
		default:
			off++;
			while ((off < len) && (buf[off] != '\r') && (buf[off] != '\n')) {
				off++;
			}
		}
	}

	if (!header && (off == len))
		header = len;

	if (!header || (need_recode(buf, header) & 1)) {
		/* no empty line found: treat whole message as header. But this means we have
		 * 8bit characters in header which is a bug in the client that we can't handle */
		write_status("D5.6.3 message contains unencoded 8bit data in message header");
		net_conn_shutdown(shutdown_abort);
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
		write_status("D5.6.3 syntax error in Content-Type message header");
		net_conn_shutdown(shutdown_abort);
	} else {
		if (!body_recode) {
			wrap_header(buf, header);
		} else if (cenc.len) {
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
recode_qp(const char *buf, const off_t len)
{
	unsigned int idx = 0;
	char sendbuf[1280];
	size_t chunk = 0;	/* size of the chunk to copy into sendbuf */
	off_t off = 0;
	int llen = 0;		/* length of this line, needed for qp line break */

	assert(len >= 0);

	if (len <= 0)
		return;

	while (off < len) {
		if (idx > 0) {
			/* flush out everything already in the buffer */
			netnwrite(sendbuf, idx);
			lastlf = (sendbuf[idx - 1] == '\n');
			idx = 0;
		}

		while ((idx + chunk < sizeof(sendbuf) - 11) && (off + (off_t) chunk < len)) {
			if (buf[off + chunk] == '\r') {
				chunk++;
				llen = 0;
				if (buf[off + chunk] == '\n') {
					/* valid CRLF pair, chunk can accumulate further */
					chunk++;
				} else {
					/* CR without following LF, copy chunk, insert LF,
					 * start next chunk */
					memcpy(sendbuf + idx, buf + off, chunk);
					off += chunk;
					idx += chunk;
					sendbuf[idx++] = '\n';
					chunk = 0;
				}
				continue;
			} else if (buf[off + chunk] == '\n') {
				/* LF without preceding CR, copy chunk without LF, insert
				 * CRLF, skip LF in input, start next chunk */
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
				memcpy(sendbuf + idx, buf + off, chunk);
				off += chunk;
				idx += chunk;
				chunk = 0;
				/* recode last character if it was whitespace */
				if ((idx > 0) && ((sendbuf[idx - 1] == '\t') || (sendbuf[idx - 1] == ' '))) {
					/* if the next character does not need recoding add
					 * it to this line if this line would end in a whitespace
					 * otherwise. " x" is shorter than "=20". */
					if ((off < len) &&
							((buf[off] > 32) && (buf[off] < 127) &&
							(buf[off] != '='))) {
						sendbuf[idx++] = buf[off++];
					} else if (sendbuf[idx - 1] == '\t') {
						sendbuf[idx - 1] = '=';
						sendbuf[idx++] = '0';
						sendbuf[idx++] = '9';
					} else {
						assert(sendbuf[idx - 1] == ' ');
						sendbuf[idx - 1] = '=';
						sendbuf[idx++] = '2';
						sendbuf[idx++] = '0';
					}
				}
				sendbuf[idx++] = '=';
				sendbuf[idx++] = '\r';
				sendbuf[idx++] = '\n';
				llen = 0;
			}

			if (!llen && (buf[off + chunk] == '.')) {
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
	unsigned int recodeflag;

	recodeflag = need_recode(buf, len);

	off = qp_header(buf, len, &boundary, &multipart, (recodeflag & 0x3));

	if (!multipart) {
		if (recodeflag & 0x3)
			recode_qp(buf + off, len - off);
		else
			send_plain(buf + off, len - off);
	} else {
		off_t nextoff = find_boundary(buf + off, len - off, &boundary);
		int nr;
		int islast = 0;	/* set to one if MIME end boundary was found */

		if (!nextoff) {
			/* huh? message declared as multipart, but without any boundary? */
			/* add boundary */
			netwrite("\r\n--");
			netnwrite(boundary.s, boundary.len);
			netwrite("\r\n");
			/* add Content-Transfer-Encoding header and extra newline */
			recodeheader();
			netwrite("\r\n");
			/* recode body */
			recode_qp(buf + off, len - off);
			/* add end boundary */
			netwrite("\r\n--");
			netnwrite(boundary.s, boundary.len);
			netwrite("--\r\n");
			lastlf = 1;
			return;
		}

		/* check and send or discard MIME preamble */
		if ( (nr = need_recode(buf + off, nextoff)) ) {
			log_write(LOG_ERR, "discarding invalid MIME preamble");
			netwrite("\r\ninvalid MIME preamble was dicarded.\r\n\r\n--");
			netnwrite(boundary.s, boundary.len);
			off += nextoff;
		} else {
			send_plain(buf + off, nextoff);
			off += nextoff;
		}

		if ((off < len) && (buf[off] == '-')) {
			/* wow: end-boundary as first boundary. What next? Flying cows? */

			/* first: add normal boundary to make this a more or less usefull MIME message, then add an end boundary */
			netwrite("\r\n\r\n--");
			netnwrite(boundary.s, boundary.len);
			netwrite("--");
			islast = 1;
			off += 2;
		}

		off += skip_tpad(buf + off, len - off);
		netwrite("\r\n");

		while ((off < len) && !islast && (nextoff = find_boundary(buf + off, len - off, &boundary))) {
			off_t partlen = nextoff - boundary.len - 2;

			nr = need_recode(buf + off, partlen);
			if ((!(smtpext & 0x008) && (nr & 1)) || (nr & 6)) {
				send_qp(buf + off, partlen);
			} else {
				send_plain(buf + off, partlen);
			}
			netwrite("--");
			netnwrite(boundary.s, boundary.len);
			off += nextoff;
			if ((off < len) && (buf[off] == '-')) {
				/* this is end boundary */
				netwrite("--");
				off += 2;
				islast = 1;
			}
			off += skip_tpad(buf + off, len - off);

			if ((off == len) && !islast) {
				netwrite("--\r\n");
				lastlf = 1;
				return;
			}
			netwrite("\r\n");
			if (off == len)
				return;
		}

		/* Look if we have seen the final MIME boundary yet. If not, add it. */
		if (!islast) {
			send_qp(buf + off, len - off);
			netwrite("\r\n--");
			netnwrite(boundary.s, boundary.len);
			netwrite("--\r\n");
		} else if (need_recode(buf + off, len - off)) {
			/* All normal MIME parts are processed now, what follow is the epilogue.
			 * Check if it needs recode. If it does, it is broken and can simply be
			 * discarded */
			log_write(LOG_ERR, "discarding invalid MIME epilogue");
			netwrite("\r\ninvalid MIME epilogue has been discarded.\r\n");
			lastlf = 1;
		} else {
			send_plain(buf + off, len - off);
		}
	}
}

/**
 * send the message data
 *
 * @param recodeflag the result of need_recode() for the input data
 */
void
send_data(unsigned int recodeflag)
{
	int num;

	successmsg[2] = "";
	netwrite("DATA\r\n");
	if ( (num = netget()) != 354) {
		const char *msg[] = { num >= 500 ? "D5" : "Z4", ".3.0 remote host rejected DATA command: ",
				linein.s + 4 };
		write_status_m(msg, 3);
		net_conn_shutdown(shutdown_clean);
	}
#ifdef DEBUG_IO
	in_data = 1;
#endif

	if ((!(smtpext & 0x008) && (recodeflag & 1)) || (recodeflag & 6)) {
		successmsg[2] = "(qp recoded) ";
		send_qp(msgdata, msgsize);
	} else {
		send_plain(msgdata, msgsize);
	}
	if (lastlf) {
		netwrite(".\r\n");
	} else {
		netwrite("\r\n.\r\n");
	}

#ifdef DEBUG_IO
	in_data = 0;
#endif
	checkreply("KZD", successmsg, 1);
}
