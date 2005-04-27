#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/mman.h>
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
#include "starttlsr.h"
#include "qrdata.h"

int socketd;
struct string heloname;
unsigned int smtpext;
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

void __attribute__ ((noreturn))
err_conf(const char *errmsg)
{
	const char *msg[] = {errmsg, NULL};
	err_confn(msg);
}

void __attribute__ ((noreturn))
err_confn(const char **errmsg)
{
	log_writen(LOG_ERR, errmsg);
	/* write text including 0 byte */
	write(1, "Z4.3.0 Configuration error.\n", 29);
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

#ifdef DEBUG_IO
	j = open("control/Qremote_debug", O_RDONLY);
	do_debug_io = (j > 0);
	if (j > 0)
		close(j);
#endif
}

static void
quitmsg(void)
{
	netwrite("QUIT\r\n");
	do {
/* don't care about what he replies: we want to quit, if he don't want us to he must pay money *eg* */
		if (net_read()) {
			log_write(LOG_ERR, "network read error while waiting for QUIT reply");
			break;
		}
	} while ((linelen >= 4) && (linein[3] == '-'));
	close(socketd);
}

void __attribute__ ((noreturn))
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
	const struct ips *m = mx;

	free(partner_fqdn);
	free(rhost);

	/* find active mx */
	while (m->priority)
		m = m->next;

	if (ask_dnsname(&m->addr, &partner_fqdn)) {
		if (errno != ENOMEM) {
			rhost = malloc(INET6_ADDRSTRLEN + 2);
		}
		if (errno == ENOMEM) {
			err_mem(1);
		}
		rhost[0] = '[';
		/* there can't be any errors here ;) */
		(void) inet_ntop(AF_INET6, &m->addr, rhost + 1, INET6_ADDRSTRLEN);
		rhostlen = strlen(rhost);
		rhost[rhostlen++] = ']';
		rhost[rhostlen] = '\0';
	} else {
		rhostlen = strlen(partner_fqdn);
		rhost = malloc(rhostlen + INET6_ADDRSTRLEN + 3);

		if (!rhost) {
			err_mem(1);
		}

		memcpy(rhost, partner_fqdn, rhostlen);
		rhost[rhostlen++] = ' ';
		rhost[rhostlen++] = '[';
		/* there can't be any errors here ;) */
		(void) inet_ntop(AF_INET6, &m->addr, rhost + rhostlen, INET6_ADDRSTRLEN);
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
int
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
	if (linelen < 3)
		goto syntax;
	if ((linelen > 3) && ((linein[3] != ' ') && (linein[3] != '-')))
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
 * @pre: text to write to stdout before server reply if mask matches
 * @mask: bitmask for pre: 1: 2xx, 2: 4xx, 3: 5xx
 *
 * returns: the SMTP result code
 *
 * status must be at least 3 bytes long but only the first 3 will have any effect. The first
 * one is the status code writen on success (server response is 2xx), the second on on temporary
 * error (4xx) and the third on permanent error (5xx). If no status code should be written status
 * must be set to NULL. If the first character in status is ' ' no message will be printed for
 * success messages.
 */
int
checkreply(const char *status, const char **pre, const int mask)
{
	int res;
	int ignore = 0;

	res = netget();
	if (status) {
		int m;

		if ((res >= 211) && (res <= 252)) {
			if (status[0] == ' ') {
				ignore = 1;
			} else {
				write(1, status, 1);
			}
			m = 1;
		} else if ((res >= 421) && (res <= 452)) {
			write(1, status + 1, 1);
			m = 2;
		} else {
			write(1, status + 2, 1);
			m = 3;
		}
		if (!ignore) {
			if (pre && (m & mask)) {
				int i = 0;
	
				while (pre[i]) {
					write(1, pre[i], strlen(pre[i]));
					i++;
				}
			}
			write(1, linein, linelen);
		}
	}
	while (linein[3] == '-') {
		/* ignore the SMTP code sent here, if it's different from the one before the server is broken */
		(void) netget();
		if (status && !ignore) {
			write(1, linein, linelen);
			write(1, "\n", 1);
		}
	}

	if (status && !ignore)
		write(1, "", 1);
	/* this allows us to check for 2xx with (x < 300) later */
	if (res < 200)
		res = 599;
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

void __attribute__ ((noreturn))
dieerror(int error)
{
	switch (error) {
		case ETIMEDOUT:	write(1, "Zconnection to remote server died\n", 35);
				log_write(LOG_WARNING, "connection timed out");
				break;
		case ECONNRESET:write(1, "Zconnection to remote timed out\n", 33);
				log_write(LOG_WARNING, "connection died");
				break;
	}
	_exit(0);
}

static const char *mailerrmsg[] = {"Connected to ", NULL, " but sender was rejected", NULL};

int
main(int argc, char *argv[])
{
	const char *netmsg[7];
	int rcptstat = 1;	/* this means: all recipients have been rejected */
	int i;
	struct ips *mx = NULL;
	int rcptcount = argc - 3;
	struct stat st;
	char sizebuf[ULSTRLEN];
#ifndef __USE_FILE_OFFSET64
	__off_t off;
#else
	__off64_t off;
#endif

	setup();

	if (rcptcount <= 0) {
		log_write(LOG_CRIT, "too few arguments");
		write(1, "Zinternal error: Qremote called with invalid arguments\n", 56);
		return 0;
	}

	getmxlist(argv[1], &mx);

	/* this shouldn't fail normally: qmail-rspawn did it before successfully */
	i = fstat(0, &st);
	if (i) {
		if (errno == ENOMEM)
			err_mem(0);
		log_write(LOG_CRIT, "can't fstat() input");
		write(1, "Zinternal error: can't fstat() input\n", 38);
		return 0;
	}
	msgsize = st.st_size;
	msgdata = mmap(NULL, msgsize, PROT_READ, MAP_SHARED, 0, 0);

	if (msgdata == MAP_FAILED) {
		log_write(LOG_CRIT, "can't mmap() input");
		write(1, "Zinternal error: can't mmap() input\n", 37);
		return 0;
	}
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
		if (linein[3] != ' ') {
			const char *dropmsg[] = {"invalid greeting from ", NULL, NULL};

			getrhost(mx);
			dropmsg[1] = rhost;
			log_writen(LOG_WARNING, dropmsg);
			quitmsg();
			continue;
		}
	} while (greeting());

	getrhost(mx);
	freeips(mx);
	mailerrmsg[1] = rhost;

	if (smtpext & 0x04) {
		if (tls_init()) {
			if (greeting()) {
				write(1, "ZEHLO failed after STARTTLS\n", 29);
				quit();
			}
			successmsg[4] = " encrypted";
		}
	}

/* check if message is plain ASCII or not */
	off = msgsize;
	ascii = 1;

	while (off > 0) {
		off--;
		if (msgdata[off] < 0) {
			ascii = 0;
			break;
		}
	}

	netmsg[0] = "MAIL FROM:<";
	netmsg[1] = argv[2];
	netmsg[2] = ">";
	netmsg[3] = NULL;
/* ESMTP SIZE extension */
	if (smtpext & 0x01) {
		netmsg[3] = " SIZE=";
		ultostr(msgsize, sizebuf);
		netmsg[4] = sizebuf;
		netmsg[5] = NULL;
	}
/* ESMTP 8BITMIME extension */
	if (smtpext & 0x08) {
		int idx;

		idx = (smtpext & 0x01) ? 5 : 3;

		netmsg[idx++] = ascii ? " BODY=7BIT" : " BODY=8BITMIME";
		netmsg[idx] = NULL;
	}
	net_writen(netmsg);

	netmsg[3] = NULL;
	if (smtpext & 0x02) {
/* server allows PIPELINING: first send all the messages, then check the replies.
 * This allows to hide network latency. */
		netmsg[0] = "RCPT TO:<";
		for (i = 3; i < argc; i++) {
			netmsg[1] = argv[i];
			net_writen(netmsg);
		}
/* MAIL FROM: reply */
		if (checkreply(" ZD", mailerrmsg, 6) >= 300) {
			for (i = rcptcount; i > 0; i--)
				checkreply(NULL, NULL, 0);
			quit();
		}
/* RCPT TO: replies */
		for (i = rcptcount; i > 0; i--) {
			if (checkreply(" sh", NULL, 0) < 300) {
				write(1, "r", 2);
				rcptstat = 0;
			}
		}
		if (rcptstat)
			quit();
	} else {
/* server does not allow pipelining: we must do this one by one */
		if (checkreply(" ZD", mailerrmsg, 6) >= 300)
			quit();
		netmsg[0] = "RCPT TO:<";
		for (i = 3; i < argc; i++) {
			netmsg[1] = argv[i];
			net_writen(netmsg);
			if (checkreply(" sh", NULL, 0) < 300) {
				write(1, "r", 2);
				rcptstat = 0;
			}
		}
		if (rcptstat)
			quit();
	}
	successmsg[0] = rhost;
	if (smtpext & 0x10) {
		send_bdat();
	} else {
		send_data();
	}
	quit();
}
