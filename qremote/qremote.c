#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include "netio.h"
#include "dns.h"
#include "control.h"
#include "log.h"
#include "match.h"
#include "sstring.h"
#include "conn.h"
#include "qremote.h"

int socketd;
static struct string heloname;
static unsigned int smtpext;
char *rhost;
size_t rhostlen;
char *partner_fqdn;

static void quitmsg(void);

void __attribute__ ((noreturn))
err_mem(const int doquit)
{
	if (doquit)
		quitmsg();
/* write text including 0 byte */
	write(1, "Z4.3.0 Out of memory.\n", 23);
	_exit(0);
}

static void __attribute__ ((noreturn))
err_conf(const char *errmsg)
{
	log_write(LOG_ERR, errmsg);
/* write text including 0 byte */
	write(1, "ZConfiguration error. (#4.3.0)\n", 32);
	_exit(0);
}

static void
setup(void)
{
	int j;

#ifdef USESYSLOG
	openlog("Qremote", LOG_PID, LOG_MAIL);
#endif

	if (chdir(AUTOQMAIL)) {
		err_conf("cannot chdir to qmail directory");
	}

	if ( (j = loadoneliner("control/helohost", &heloname.s, 1) ) < 0 ) {
		if ( ( j = loadoneliner("control/me", &heloname.s, 0) ) < 0 ) {
			err_conf("can open neither control/helohost nor control/me");
		}
		if (domainvalid(heloname.s)) {
			err_conf("control/me contains invalid name");
		}
	} else {
		if (domainvalid(heloname.s)) {
			err_conf("control/helohost contains invalid name");
		}
	}
	if ( (j = loadintfd(open("control/timeoutremote", O_RDONLY), &timeout, 320)) < 0) {
		err_conf("parse error in control/timeoutremote");
	}

	heloname.len = j;
}

static void
quitmsg(void)
{
	netwrite("QUIT\r\n");
	do {
/* don't care about what he replies: we want to quit, if he don't want us to he must pay money *eg* */
		if (net_read()) {
			// error handling
		}
	} while ((linelen >= 4) && (linein[3] == '-'));
	close(socketd);
}

static void __attribute__ ((noreturn))
quit(void)
{
	quitmsg();
	exit(0);
}

/**
 *
 *
 *
 */
static inline void
getrhost(const struct ips *mx)
{
	if (ask_dnsname(&mx->addr, &partner_fqdn)) {

		if (errno != ENOMEM) {
			rhost = malloc(INET6_ADDRSTRLEN + 2);
		}
		if (errno == ENOMEM) {
			err_mem(1);
		}
		rhost[0] = '[';
		/* there can't be any errors here ;) */
		(void) inet_ntop(AF_INET6, &mx->addr, rhost + 1, INET6_ADDRSTRLEN);
		rhostlen = strlen(rhost);
		rhost[rhostlen++] = ']';
		rhost[rhostlen] = '\0';
	} else {
		rhostlen = strlen(partner_fqdn);
		rhost = malloc(rhostlen + INET6_ADDRSTRLEN + 3);

		if (!rhost) {
			err_mem(1);
		}

		rhost[rhostlen++] = ' ';
		rhost[rhostlen++] = '[';
		/* there can't be any errors here ;) */
		(void) inet_ntop(AF_INET6, &mx->addr, rhost + rhostlen, INET6_ADDRSTRLEN);
		rhostlen = strlen(rhost);
		rhost[rhostlen++] = ']';
		rhost[rhostlen] = '\0';
	}
}


/**
 * netget - get one line from the network, handle all error cases
 *
 * returns: SMTP return code of the message
 */
static int
netget(void)
{
	int q, r;

	if (net_read()) {
		switch (errno) {
			case ENOMEM:	err_mem(1);
			case EINVAL:
			case E2BIG:	goto syntax;
			default:	{
						char *tmp = strerror(errno);

						write(1, "Z", 1);
						write(1, tmp, strlen(tmp) + 1);
						quit();
			}
		}
	}
	if (linelen < 4)
		goto syntax;
	if ((linein[3] != ' ') && (linein[3] != '-'))
		goto syntax;
	r = linein[0] - '0';
	if ((r < 2) || (r > 5))
		goto syntax;
	q = linein[1] - '0';
	if ((q < 0) || (q > 9))
		goto syntax;
	r = r * 10 + q;
	q = linein[2] - '0';
	if ((q < 0) || (q > 9))
		goto syntax;
	return r * 10 + q;
syntax:
	/* if this fails we're already in bad trouble */
	(void) write(1, "Zsyntax error in server reply\n", 31);
	quit();
}

/**
 * checkreply - check the reply of the server
 *
 * @status: status codes to print or NULL if not to
 *
 * returns: the SMTP result code
 *
 * status must be at least 3 bytes long but only the first 3 will have any effect. The first
 * one is the status code writen on success (server response is 2xx), the second on on temporary
 * error (4xx) and the third on permanent error (5xx). If no status code should be written status
 * must be set to NULL. If the first character in status is ' ' no message will be printed for
 * success messages.
 */
static int
checkreply(const char *status)
{
	int res;
	int ignore = 0;

	res = netget();
	if (status) {
		if ((res >= 200) && (res < 300)) {
			if (status[0] == ' ') {
				ignore = 1;
			} else {
				write(1, status, 1);
			}
		} else if ((res >= 400) && (res < 500)) {
			write(1, status + 1, 1);
		} else {
			write(1, status + 2, 1);
		}
		write(1, linein, linelen);
	}
	while (linein[3] == '-') {
		if (netget() != res) {
			// handle error case
		}
		if (status && !ignore) {
			write(1, linein, linelen);
			write(1, "\n", 1);
		}
	}

	if (status && !ignore)
		write(1, "", 1);
	return res;
}

static unsigned long remotesize;

static int
cb_size(void)
{
	char *s;

	if (!linein[8])
		return 0;

	remotesize = strtoul(linein + 8, &s, 10);
	return *s;
}

/**
 * greeting - greet the server, try ehlo and fall back to helo if needed
 *
 * returns: 0 if greeting succeeded or 1 on error
 */
static int
greeting(void)
{
	struct smtpexts {
		const char *name;
		unsigned int len;	/* strlen(name) */
		int (*func)(void);	/* used to handle arguments to this extension, NULL if no arguments allowed */
	} extensions[] = {
		{ .name = "SIZE",	.len = 4,	.func = cb_size	}, /* 0x01 */
		{ .name = "PIPELINING",	.len = 10,	.func = NULL	}, /* 0x02 */
		{ .name = "STARTTLS",	.len = 8,	.func = NULL	}, /* 0x04 */
		{ .name = "8BITMIME",	.len = 8,	.func = NULL	}, /* 0x08 */
		{ .name = "CHUNKING",	.len = 8,	.func = NULL	}, /* 0x10 */
		{ .name = NULL }
	};
	const char *cmd[3];
	int s;			/* SMTP status */

	cmd[0] = "EHLO ";
	cmd[1] = heloname.s;
	cmd[2] = NULL;
	net_writen(cmd);
	do {
		s = netget();
		if (s == 250) {
			int j = 0;

			while (extensions[j].name) {
				if (!strncasecmp(linein + 4, extensions[j].name, extensions[j].len)) {
					if (extensions[j].func) {
						if (!extensions[j].func()) {
							smtpext |= (1 << j);
							break;
						}
					} else {
						if (!*(linein + 4 + extensions[j].len)) {
							smtpext |= (1 << j);
							break;
						}
					}
				}
				j++;
			}
		}
	} while (linein[3] == '-');

	if (s != 250) {
/* EHLO failed, try HELO */
		cmd[0] = "HELO ";
		net_writen(cmd);
		do {
			s = netget();
		} while (linein[3] == '-');
		if (s == 250) {
			smtpext = 0;
		} else {
			return 1;
		}
	}
	return 0;
}

static void
send_data(void)
{
	char sendbuf[1205];
	unsigned int idx = 0;
	int num;
	int lastlf = 0;		/* set if last byte sent was a LF */

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
	checkreply("KZD");
	return;
readerr:
	write(1, "Zerror reading mail, aborting transfer.\n", 41);
	exit(0);
}

static void
send_bdat(void)
{
	char sendbuf[2048];
	int num;
	int last = 0;

	while ( (num = read(42, sendbuf, sizeof(sendbuf) - 1)) ) {
		char chunklen[5];
		const char *netmsg[] = {"BDAT ", chunklen, NULL, NULL};

		if (num < 0)
			goto readerr;
/* Try to read one byte more. If this causes EOF we can mark this the last chunk */
		last = read(42, sendbuf + num, 1);
		if (last < 0) {
			goto readerr;
		} else if (!last) {
			netmsg[2] = " LAST";
		} else {
			num += 1;
			last = 0;
		}
		ultostr(num, chunklen);
		net_writen(netmsg);
		netnwrite(sendbuf, num);
		if (last)
			break;
		if (checkreply(" ZD") != 250)
			quit();
	}
	if (!last)
		netwrite("BDAT 0 LAST\r\n");
	checkreply("KZD");
	return;
readerr:
	write(1, "Zerror reading mail, aborting transfer.\n", 41);
	exit(0);
}

/**
 * err_mail - handle error reply to MAIL FROM command
 *
 * @s: status code returned by server
 */
static void
err_mail(const int s)
{
	write(1, s > 500 ? "D" : "Z", 1);
	write(1, "Connected to ", 13);
	write(1, rhost, rhostlen);
	/* write text including 0 byte */
	write(1, " but sender was rejected", 25);
}

int
main(int argc, char *argv[])
{
	const char *netmsg[6];
	int rcptstat = 1;	/* this means: all recipients have been rejected */
	int i;
	struct ips *mx = NULL;
	int rcptcount = argc - 4;

	setup();

	if (rcptcount <= 0) {
		log_write(LOG_CRIT, "too few arguments");
		return 0;
	}

	for (i = strlen(argv[3]) - 1; i >= 0; i--) {
		if ((argv[3][i] < '0') || (argv[3][i] > '9')) {
			log_write(LOG_CRIT, "third argument is not a number");
			return 0;
		}
	}

	getmxlist(argv[1], &mx);

	dup2(0, 42);

/* for all MX entries we got: try to enable connection, check if the SMTP server wants us
 * (sends 220 response) and EHLO/HELO succeeds. If not, try next. If none left, exit. */
	do {
		tryconn(mx);
		dup2(socketd, 0);
		if (netget() != 220) {
			quitmsg();
			continue;
		}
	} while (greeting());

	getrhost(mx);
	freeips(mx);

	netmsg[0] = "MAIL FROM:<";
	netmsg[1] = argv[2];
/* ESMTP SIZE extension */
	if (smtpext & 1) {
		netmsg[2] = "> SIZE=";
		netmsg[3] = argv[3];
		netmsg[4] = NULL;
	} else {
		netmsg[2] = ">";
		netmsg[3] = NULL;
	}
	net_writen(netmsg);
	if (smtpext & 1) {
		netmsg[2] = ">";
		netmsg[3] = NULL;
	}
	if (smtpext & 2) {
/* server allows PIPELINING: first send all the messages, then check the replies.
 * This allows to hide network latency. */
		netmsg[0] = "RCPT TO:<";
		for (i = 4; i < argc; i++) {
			netmsg[1] = argv[i];
			net_writen(netmsg);
		}
/* MAIL FROM: reply */
		if ( (i = checkreply(NULL)) >= 300) {
			err_mail(i);

			for (i = rcptcount; i > 0; i--)
				checkreply(NULL);
			quit();
		}
/* RCPT TO: replies */
		for (i = rcptcount; i > 0; i--) {
			if (checkreply("rsh") < 300)
				rcptstat = 0;
		}
		if (rcptstat)
			quit();
	} else {
/* server does not allow pipelining: we must do this one by one */
		net_read();
		if ( (i = checkreply(NULL)) >= 300)
			err_mail(i);
		netmsg[0] = "RCPT TO:<";
		for (i = 4; i < argc; i++) {
			netmsg[1] = argv[i];
			net_writen(netmsg);
			if (checkreply("rsh") < 300)
				rcptstat = 0;
		}
		if (rcptstat)
			quit();
	}
	if (smtpext & 0x10) {
		send_bdat();
	} else {
		send_data();
	}
	quit();
}
