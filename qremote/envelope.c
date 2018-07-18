#include <qremote/qremote.h>

#include <fmt.h>
#include <log.h>
#include <netio.h>
#include <qremote/client.h>
#include <qremote/greeting.h>
#include <qremote/qrdata.h>

int
send_envelope(const unsigned int recodeflag, const char *sender, int rcptcount, char **rcpts)
{
	const char *mailerrmsg[] = { "Connected to ", rhost, " but sender was rejected\n", NULL };
	const char *netmsg[10] = { "MAIL FROM:<", sender };
	int rcptstat = 1;	/* this means: all recipients have been rejected */
	char sizebuf[ULSTRLEN];
	unsigned int lastmsg = 2;	/* last message in array */

/* ESMTP SIZE extension */
	if (smtpext & esmtp_size) {
		netmsg[lastmsg++] = "> SIZE=";
		ultostr(msgsize, sizebuf);
		netmsg[lastmsg++] = sizebuf;
	} else {
		netmsg[lastmsg++] = ">";
	}
/* ESMTP 8BITMIME extension */
	if (smtpext & esmtp_8bitmime) {
		netmsg[lastmsg++] = (recodeflag & 1) ? " BODY=8BITMIME" : " BODY=7BIT";
	}
	if (smtpext & esmtp_pipelining) {
/* server allows PIPELINING: first send all the messages, then check the replies.
 * This allows to hide network latency. */
		/* batch the first recipient with the from */
		netmsg[lastmsg++] = "\r\nRCPT TO:<";
		netmsg[lastmsg++] = rcpts[0];
		netmsg[lastmsg++] = ">\r\n";
		netmsg[lastmsg] = NULL;
		net_write_multiline(netmsg);

		lastmsg = 1;
		netmsg[0] = "RCPT TO:<";
		for (int i = 1; i < rcptcount; i++) {
			netmsg[lastmsg++] = rcpts[i];
			if ((i == rcptcount - 1) || ((i % 4) == 3)) {
				netmsg[lastmsg++] = ">\r\n";
				netmsg[lastmsg] = NULL;
				net_write_multiline(netmsg);
				lastmsg = 1;
			} else {
				netmsg[lastmsg++] = ">\r\nRCPT TO:<";
			}
		}
/* MAIL FROM: reply */
		if (checkreply(" ZD", mailerrmsg, 6) >= 300) {
			for (int i = rcptcount; i > 0; i--)
				checkreply(NULL, NULL, 0);
			return 1;
		}
/* RCPT TO: replies */
		for (int i = rcptcount; i > 0; i--) {
			if (checkreply("rsh", NULL, 8) < 300)
				rcptstat = 0;
		}
	} else {
/* server does not allow pipelining: we must do this one by one */
		netmsg[lastmsg] = NULL;
		net_writen(netmsg);

		if (checkreply(" ZD", mailerrmsg, 6) >= 300)
			return 1;

		netmsg[0] = "RCPT TO:<";
		netmsg[2] = ">";
		netmsg[3] = NULL;

		for (int i = 0; i < rcptcount; i++) {
			netmsg[1] = rcpts[i];
			net_writen(netmsg);
			if (checkreply("rsh", NULL, 8) < 300)
				rcptstat = 0;
		}
	}

	return rcptstat;
}
