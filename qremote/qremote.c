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

int socketd;
static struct string heloname;
static unsigned int smtpext;

static void
setup(void)
{
	int j;

#ifdef USESYSLOG
	openlog("Qremote", LOG_PID, LOG_MAIL);
#endif

	if (chdir(AUTOQMAIL)) {
		log_write(LOG_ERR, "cannot chdir to qmail directory");
		_exit(0);
	}

	if ( (j = loadoneliner("control/helohost", &heloname.s, 1) ) < 0 ) {
		if ( ( j = loadoneliner("control/me", &heloname.s, 0) ) < 0 ) {
			log_write(LOG_ERR, "can open neither control/helohost nor control/me");
			_exit(0);
		}
		if (domainvalid(heloname.s)) {
			log_write(LOG_ERR, "control/me contains invalid name");
			_exit(0);
		}
	} else {
		if (domainvalid(heloname.s)) {
			log_write(LOG_ERR, "control/helohost contains invalid name");
			_exit(0);
		}
	}
	if ( (j = loadintfd(open("control/timeoutremote", O_RDONLY), &timeout, 320)) < 0) {
		log_write(LOG_ERR, "parse error in control/timeoutremote");
		_exit(0);
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
 * netget - get one line from the network, handle all error cases
 *
 * returns: SMTP return code of the message
 */
static int
netget(void)
{
	int q, r;

	if (net_read())
		goto error;
	if (linelen < 4) {
		if (write(1, "server reply too short\n", 23) < 0)
			quit();
	}
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
error:
	// add error handling
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
 * must be set to NULL.
 */
static int
checkreply(const char *status)
{
	int res;

	res = netget();
	if (status) {
		if ((res >= 200) && (res < 300)) {
			write(1, status, 1);
		} else if ((res >= 400) && (res < 500)) {
			write(1, status + 1, 1);
		} else {
			write(1, status + 2, 1);
		}
		write(5, linein, linelen);
	}
	while (linein[3] == '-') {
		if (netget() != res) {
			// handle error case
		}
		if (status) {
			write(1, linein, linelen);
			write(1, "\n", 1);
		}
	}

	if (status)
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
		int (*func)(void);
	} extensions[] = {
		{ .name = "SIZE",	.len = 4,	.func = cb_size	}, /* 0x01 */
		{ .name = "PIPELINING",	.len = 10,	.func = NULL	}, /* 0x02 */
		{ .name = "STARTTLS",	.len = 8,	.func = NULL	}, /* 0x04 */
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
						if (!*(linein + 5 + extensions[j].len)) {
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

int
main(int argc, char *argv[])
{
	const char *netmsg[6];
	int i, rcptstat;
	struct ips *mx;

	setup();

	if (argc < 5) {
		log_write(LOG_CRIT, "too few arguments");
		return 0;
	}

	for (i = strlen(argv[2]) - 1; i >= 0; i--) {
		if ((argv[2][i] < '0') || (argv[2][i] > '9')) {
			log_write(LOG_CRIT, "second argument is not a number");
			return 0;
		}
	}

	getmxlist(argv[1], &mx);

	dup2(socketd,0);

/* for all MX entries we got: try to enable connection, check if the SMTP server wants us (sends 220 response) and
 * or EHLO/HELO succeeds. If not, try next. If none left, exit. */
	do {
		tryconn(mx);
		if (netget() != 220) {
			quitmsg();
			continue;
		}
	} while (greeting());

	freeips(mx);

	netmsg[0] = "MAIL FROM:<";
	netmsg[1] = argv[3];
/* ESMTP SIZE extension */
	if (smtpext & 1) {
		netmsg[2] = "> SIZE=";
		netmsg[3] = argv[2];
		netmsg[4] = NULL;
	} else {
		netmsg[2] = ">";
		netmsg[3] = NULL;
	}
	net_writen(netmsg);
	if (smtpext & 2) {
/* server allows PIPELINING: first send all the messages, then check the replies. This allows to hide network latency */
		write(1, linein, linelen);write(5,"\n",1);
		netmsg[0] = "RCPT TO:<";
		rcptstat = 1;	/* this means: all recipients have been rejected */
		for (i = 4; i < argc; i++) {
			netmsg[1] = argv[i];
			net_writen(netmsg);
		}
/* MAIL FROM: reply */
		if (checkreply(NULL) >= 300) {
#warning FIXME: write error message to stdout
			for (i = 4; i < argc; i++)
				checkreply(NULL);
			quit();
		}
		for (i = 4; i < argc; i++) {
			if (checkreply("rsh") < 300)
				rcptstat = 0;
		}
		if (rcptstat)
			quit();
	} else {
/* server does not allow pipelining: we must do this one by one */
		net_read();
		write(1, linein, linelen);write(1,"\n",1);
		netmsg[0] = "RCPT TO:<";
		rcptstat = 1;	/* this means: all recipients have been rejected */
		for (i = 4; i < argc; i++) {
			netmsg[1] = argv[i];
			net_writen(netmsg);
			if (checkreply("rsh") < 300)
				rcptstat = 0;
		}
		if (rcptstat)
			quit();
	}
	netwrite("DATA\r\n");
	if (netget() != 354)
		quit();
	netwrite("Subject: test qremote\r\n\r\n.\r\n");
	checkreply("KZD");
	quit();
}
