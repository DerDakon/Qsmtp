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

int sd;
struct string heloname;
static unsigned int smtpext;
static unsigned long targetport = 25;

int
conn(const struct in6_addr remoteip)
{
	struct sockaddr_in6 sock;
	int rc;

	sd = socket(PF_INET6, SOCK_STREAM, 0);

	if (sd < 0)
		return errno;

	sock.sin6_family = AF_INET6;
	sock.sin6_port = 0;
//	sock.sin6_flowinfo = 0;
	sock.sin6_addr = in6addr_any;
//	sock.sin6_scope_id = 0;

	rc = bind(sd, &sock, sizeof(sock));

	if (rc)
		return errno;

	sock.sin6_port = htons(targetport);
	sock.sin6_addr = remoteip;

	rc = connect(sd, &sock, sizeof(sock));
	if (rc)
		return errno;

	return 0;
}

/**
 * tryconn - try to estabish an SMTP connection to one of the hosts in the ip list (which is freed afterwards)
 *
 * @mx: list of IP adresses to try
 */
int
tryconn(struct ips *mx)
{
	struct ips *thisip;
	int c;

	thisip = mx;
	while (1) {
		int minpri = 65537;

		for (thisip = mx; thisip; thisip = thisip->next) {
			if (thisip->priority < minpri)
				minpri = thisip->priority;
		}
		if (minpri == 65537) {
			write(5, "can't connect to any server\n", 14);
			close(sd);
			exit(0);
		}
		for (thisip = mx; thisip; thisip = thisip->next) {
			if (thisip->priority == minpri) {
				c = conn(thisip->addr);
				if (c) {
					thisip->priority = 65537;
				} else {
					return 0;
				}
			}
		}
	}
}

void
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

	if ( (j = loadoneliner("control/helohost", &heloname.s, 0) ) < 0 ) {
		if ( ( j = loadoneliner("control/me", &heloname.s, 0) ) < 0 ) {
			log_write(LOG_ERR, "can open neither control/helohost nor control/me");
			_exit(0);
		}
		/* we ignore the other DNS errors here, the rest is fault of the admin */
		if (domainvalid(heloname.s, 0) == 1) {
			log_write(LOG_ERR, "control/me contains invalid name");
			_exit(0);
		}
	} else {
		/* we ignore the other DNS errors here, the rest is fault of the admin */
		if (domainvalid(heloname.s, 0) == 1) {
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

void
quitmsg(void)
{
	netwrite("QUIT\r\n");
	do {
/* don't care about what he replies: we want to quit, if he don't want us to he must pay money *eg* */
		if (net_read()) {
			// error handling
		}
	} while ((linelen >= 4) && (linein[3] == '-'));
	close(sd);
}

void __attribute__ ((noreturn))
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
int
netget(void)
{
	int q, r;

	if (net_read())
		goto error;
	if (linelen < 4) {
		if (write(5, "server reply too short\n", 23) < 0)
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
 * @status: status codes to print or '\0' if not to
 *
 * returns: the SMTP result code
 *
 * status must be at least 3 bytes long but only the first 3 will have any effect. The first
 * one is the status code writen on success (server response is 2xx), the second on on temporary
 * error (4xx) and the third on permanent error (5xx). If no status code should be written the
 * first character of status must be '\0', in this case the length be 1.
 */
int
checkreply(const char *status)
{
	int res;

	res = netget();
	if (*status) {
		if ((res >= 200) && (res < 300)) {
			write(5, status, 1);
		} else if ((res >= 400) && (res < 500)) {
			write(5, status + 1, 1);
		} else {
			write(5, status + 2, 1);
		}
		write(5, linein, linelen);
	}
	while (linein[3] == '-') {
		if (netget() != res) {
			// handle error case
		}
		if (*status) {
			write(5, linein, linelen);
			write(5, "\n", 1);
		}
	}

	write(5, "", 1);
	return res;
}

static unsigned long remotesize;

int
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
int
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
hascolon(const char *s, const int __attribute__ ((unused)) ignored)
{
	char *colon = strchr(s, ':');

	if (!*colon)
		return 0;
	return (*(colon + 1) != ':');
}

int
main(int argc, char *argv[])
{
	const char *netmsg[6];
	int i, rcptstat;
	struct ips *mx;
	char **smtproutes, *smtproutbuf;

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

	if (!loadlistfd(open("control/smtproutes", O_RDONLY), &smtproutbuf, &smtproutes, NULL, 0)) {
		char *target;
		unsigned int k = 0;

		while (smtproutes[k]) {
			target = strchr(smtproutes[k], ':');
			*target++ = '\0';

			if (matchdomain(argv[1], strlen(argv[1]), smtproutes[k])) {
				char *port;

				port = strchr(target, ':');
				if (port) {
					char *more;

					*port++ = '\0';
					if ((more = strchr(port, ':'))) {
						*more = '\0';
						// add username and passwort here later
					}
					targetport = strtol(port, &more, 10);
					if (*more || (targetport >= 65536)) {
						const char *logmsg[] = {"invalid port number given for \"",
									target, "\" given as target for \"",
									argv[1], "\", using 25 instead", NULL};

						log_writen(LOG_ERR, logmsg);
						targetport = 25;
					}
				}
				if (ask_dnsaaaa(target, &mx)) {
					const char *logmsg[] = {"cannot find IP address for static route \"",
									target, "\" given as target for \"",
									argv[1], "\"", NULL};

					log_writen(LOG_ERR, logmsg);
					return 0;
				}
			}
		}
		free(smtproutes);
		free(smtproutbuf);
	}

	if (!mx) {
		if (ask_dnsmx(argv[1], &mx)) {
			const char *logmsg[] = {"cannot find a mail exchanger for ", argv[1], NULL};
	
			log_writen(LOG_ERR, logmsg);
			return 0;
		}
	}

	dup2(1,5);
	dup2(sd,1);
	dup2(sd,0);

/* for all MX entries we got: try to enable connection, check if the SMTP server wants us (sends 220 response) and
 * or EHLO/HELO succeeds. If not, try next. If none left, exit. */
	do {
		tryconn(mx);
		if (netget() != 220) {
			quitmsg();
			continue;
		}
	} while (greeting());

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
		write(5, linein, linelen);write(5,"\n",1);
		netmsg[0] = "RCPT TO:<";
		rcptstat = 1;	/* this means: all recipients have been rejected */
		for (i = 4; i < argc; i++) {
			netmsg[1] = argv[i];
			net_writen(netmsg);
		}
/* MAIL FROM: reply */
		if (checkreply("") >= 300) {
#warning FIXME: write error message to stdout
			for (i = 4; i < argc; i++)
				checkreply("");
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
		write(5, linein, linelen);write(5,"\n",1);
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
