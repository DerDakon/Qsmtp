#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "netio.h"
#include "qremote.h"
#include "qrdata.h"

const char *successmsg[] = {NULL, " accepted ", NULL, "message", "", "./Remote_host_said: ", NULL};

void
send_data(void)
{
	char sendbuf[1205];
	unsigned int idx = 0;
	int num;
	int lastlf = 0;		/* set if last byte sent was a LF */

	successmsg[2] = "";
	netwrite("DATA\r\n");
	if ( (num = netget()) != 354) {
		write(1, num >= 500 ? "D5" : "Z4", 2);
		write(1, ".3.0 remote host rejected DATA command: ", 40);
		write(1, linein + 4, linelen - 3);
		quit();
	}
/* read in chunks of 80 bytes. Most MUAs use 80 chars per line for their mails so we will
 * not have more than one linebreak per chunk. Make sure there are at least 160 bytes left
 * in sendbuf so we can turn 80 "CR" _or_ "LF" into 80 "CRLF" (worst case). The last 3
 * chars are there to pad a "CRLF.CRLF" into if the message ends with no newline and don't
 * need to start another turn. */
	while ( (num = read(42, sendbuf + idx, 80)) ) {
		if (num < 0)
			goto readerr;
		while (num) {
			if ((sendbuf[idx] != '\r') && (sendbuf[idx] != '\n')) {
				if (!(smtpext & 0x08) && (sendbuf[idx] < 0)) {
/* this message has to be recoded to 7BIT somehow... */
					write(1, "Z5.6.3 message has 8 Bit characters but next server "
							"does not accept 8BITMIME", 77);
					_exit(0);
				}
				if (sendbuf[idx] == '.') {
					if ((idx && (sendbuf[idx - 1] == '\n')) || (!idx && lastlf)) {
						idx++;
						memmove(sendbuf + idx + 1, sendbuf + idx, num);
						sendbuf[idx] = '.';
					}
				}
				idx++;
				num--;
				continue;
			}
			if (sendbuf[idx] == '\r') {
				idx++;
				num--;
				/* check if this was the last byte in buffer. If it was, read one more */
				if (!num) {
					num = read(42, sendbuf + idx, 1);
					if (!num) {
						/* last byte in input stream */
						sendbuf[idx++] = '\n';
						break;
					} else if (num < 0) {
						goto readerr;
					}
				}
				if (sendbuf[idx] == '\n') {
					idx++;
					num--;
				} else {
					memmove(sendbuf + idx + 1, sendbuf + idx, num);
					sendbuf[idx++] = '\n';
				}
			} else {
				memmove(sendbuf + idx + 1, sendbuf + idx, num);
				sendbuf[idx++] = '\r';	/* insert CR before found LF */
				idx++;			/* skip this LF */
				num--;				/* one byte checked */
			}
		}
		if (idx >= sizeof(sendbuf) - 165) {
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
	checkreply("KZD", successmsg, 1);
	return;
readerr:
	write(1, "Zerror reading mail, aborting transfer.\n", 41);
	exit(0);
}

void
send_bdat(void)
{
	char sendbuf[2048];
	int num;
	int more = 1;

	successmsg[2] = "chunked ";
	while ( (num = read(42, sendbuf, sizeof(sendbuf) - 1)) ) {
		char chunklen[5];
		const char *netmsg[] = {"BDAT ", chunklen, NULL, NULL};

		if (num < 0)
			goto readerr;
/* Try to read one byte more. If this causes EOF we can mark this the last chunk */
		more = read(42, sendbuf + num, 1);
		if (more < 0) {
			goto readerr;
		} else if (!more) {
			netmsg[2] = " LAST";
		} else {
			num += 1;
		}
		ultostr(num, chunklen);
		net_writen(netmsg);
		netnwrite(sendbuf, num);
		if (!more)
			break;
		if (checkreply(" ZD", NULL, 0) != 250)
			quit();
	}
	if (more)
		netwrite("BDAT 0 LAST\r\n");
	checkreply("KZD", successmsg, 1);
	return;
readerr:
	write(1, "Zerror reading mail, aborting transfer.\n", 41);
	exit(0);
}
