#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "netio.h"
#include "qremote.h"
#include "qrdata.h"

const char *successmsg[] = {NULL, " accepted ", NULL, "message", "", "./Remote_host_said: ", NULL};
int ascii;			/* if message is plain ASCII or not */
char *msgdata;			/* message will be mmaped here */
#ifndef __USE_FILE_OFFSET64
	__off_t msgsize;	/* size of the mmaped area */
#else
	__off64_t msgsize;
#endif

void
send_data(void)
{
	char sendbuf[1205];
	unsigned int idx = 0;
	int num;
	int lastlf = 1;		/* set if last byte sent was a LF */
	size_t chunk = 0;	/* size of the chunk to copy into sendbuf */
	int ascii = 0;
#ifndef __USE_FILE_OFFSET64
	__off_t off = 0;
#else
	__off64_t off = 0;
#endif

	if (!(smtpext & 0x008) && !ascii) {
#warning FIXME: add proper quoted-printable recoding here
		write(1, "Z4.6.3 message has 8 Bit characters but next server "
				"does not accept 8BITMIME", 77);
		quit();
	}

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

	while (off < msgsize) {
		while (idx + chunk < sizeof(sendbuf) - 5) {
			if (off + chunk == msgsize) {
				break;
			} else if (msgdata[off + chunk] == '.') {
				/* no need to check for '\r' here, than we would have copied
				 * data and set chunk to 0.
				 *
				 * There are three cases where we have to double the '.':
				 * - we are in the middle of a chunk to copy and the last byte
				 *   in the input file was '\n'
				 * - this is the first byte of a chunk, sendbuf is empty and we
				 *   sent a '\n' as last character to the network before
				 * - this is the first byte in a chunk and the last byte written
				 *   into sendbuf is '\n'
				 */
				if ((chunk && (msgdata[off + chunk - 1] == '\n')) ||
						(!chunk && ((!idx && lastlf) || (idx && (sendbuf[idx - 1] == '\n'))))) {
					chunk++;
					memcpy(sendbuf + idx, msgdata + off, chunk);
					off += chunk;
					idx += chunk;
					sendbuf[idx++] = '.';
					chunk = 0;
				} else {
					chunk++;
				}
			} else if (msgdata[off + chunk] == '\r') {
				int last = (off + chunk == msgsize - 1);

				chunk++;
				if (!last && (msgdata[off + chunk] == '\n')) {
					chunk++;
				} else {
					memcpy(sendbuf + idx, msgdata + off, chunk);
					off += chunk;
					idx += chunk;
					sendbuf[idx++] = '\n';
					chunk = 0;
					if (last) {
						break;
					}
				}
			} else if (msgdata[off + chunk] == '\n') {
				/* bare '\n' */
				memcpy(sendbuf + idx, msgdata + off, chunk);
				off += chunk + 1;
				idx += chunk;
				sendbuf[idx++] = '\r';
				sendbuf[idx++] = '\n';
				chunk = 0;
			} else {
				chunk++;
			}
		}
		if (chunk) {
			chunk++;
			memcpy(sendbuf + idx, msgdata + off, chunk);
			off += chunk;
			idx += chunk;
			chunk = 0;
		}

		if (msgsize != off) {
			netnwrite(sendbuf, idx);
			lastlf = (sendbuf[idx - 1] == '\n');
			idx = 0;
		}
	}
	if (idx) {
		if (sendbuf[idx - 1] != '\n') {
			if (sendbuf[idx - 1] != '\r') {
				sendbuf[idx++] = '\r';
			}
			sendbuf[idx++] = '\n';
		}
	} else {
		if (!lastlf) {
			sendbuf[0] = '\r';
			sendbuf[1] = '\n';
			idx = 2;
		}
	}
	sendbuf[idx++] = '.';
	sendbuf[idx++] = '\r';
	sendbuf[idx++] = '\n';
	netnwrite(sendbuf, idx);
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
#ifndef __USE_FILE_OFFSET64
	__off_t off = 0;
#else
	__off64_t off = 0;
#endif

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
