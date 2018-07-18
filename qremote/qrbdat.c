#include <qremote/qrdata.h>

#include <fmt.h>
#include <log.h>
#include <netio.h>
#include <qremote/client.h>
#include <qremote/qremote.h>

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

size_t chunksize;	/**< the maximum allowed size for an outgoing send buffer in BDAT mode */

/**
 * send the message data as binary chunk
 *
 * @param recodeflag the result of need_recode() for the input data
 */
void
send_bdat(unsigned int recodeflag)
{
	int bare_cr_warning = 0;

	char *chunkbuf = malloc(chunksize);

	if (chunkbuf == NULL) {
		log_write(LOG_WARNING, "cannot allocate buffer for chunked transfer, fallback to normal transfer\n");
		send_data(recodeflag);
		return;
	}

	successmsg[2] = "chunked ";
	/* calculate length needed to send out the "BDAT <len>" stuff */
	size_t lenlen = 0;			/* "reserved" length for "BDAT <len> (LAST)?" */
	size_t i = chunksize;
	while (i) {
		lenlen++;
		i /= 10;
	}
	lenlen += 12; /* "BDAT " + " LAST" + CRLF */

#ifdef DEBUG_IO
	in_data = 1;
#endif
	for (off_t off = 0; off < msgsize; ) {
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
				} else if (bare_cr_warning == 0) {
					log_write(LOG_WARNING, "found bare CR in message\n");
					bare_cr_warning = 1;
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
		if (off != msgsize) {
#ifdef DEBUG_IO
			in_data = 0;
#endif
			if (checkreply(" ZD", NULL, 0) != 250) {
				free(chunkbuf);
				net_conn_shutdown(shutdown_clean);
			}
#ifdef DEBUG_IO
			in_data = 1;
#endif
		}
	}
#ifdef DEBUG_IO
	in_data = 0;
#endif
	free(chunkbuf);
	checkreply("KZD", successmsg, 1);
}
