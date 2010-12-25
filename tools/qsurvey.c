/** \file qsurvey.c
 \brief main functions of Qsurvey

 This file contains the main functions of Qsurvey, a simple SMTP server survey
 to check for remote SMTP server capabilities and software version.
 */
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
#include "qdns.h"
#include "control.h"
#include "log.h"
#include "match.h"
#include "sstring.h"
#include "conn.h"
#include "starttlsr.h"
#include "qremote.h"
#include "fmt.h"

int socketd;
string heloname;
unsigned int smtpext;
char *rhost;
size_t rhostlen;
char *partner_fqdn;
static int logfd;

static void quitmsg(void);

void
err_mem(const int doquit)
{
	if (doquit)
		quitmsg();
/* write text including 0 byte */
	write(1, "Z4.3.0 Out of memory.\n", 23);
	_exit(0);
}

void
err_confn(const char **errmsg)
{
	log_writen(LOG_ERR, errmsg);
	/* write text including 0 byte */
	write(1, "Z4.3.0 Configuration error.\n", 29);
	_exit(0);
}

void
err_conf(const char *errmsg)
{
	const char *msg[] = {errmsg, NULL};
	err_confn(msg);
}

static void
setup(void)
{
	int j;
	unsigned long tmp;

#undef USESYSLOG

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
	if ( (j = loadintfd(open("control/timeoutremote", O_RDONLY), &tmp, 320)) < 0) {
		err_conf("parse error in control/timeoutremote");
	}
	timeout = tmp;

	heloname.len = j;

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
	socketd = -1;
}

void
quit(void)
{
	quitmsg();
	exit(0);
}

/**
 * print remote host information to buffer
 *
 * @param mx list of MX entries, entry with priority 65538 is active
 */
static inline void
getrhost(const struct ips *mx)
{
	const struct ips *m = mx;

	free(partner_fqdn);
	free(rhost);

	/* find active mx */
	while (m->priority != 65538)
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
		partner_fqdn = NULL;
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
 * get one line from the network, handle all error cases
 *
 * @return SMTP return code of the message
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

	if (logfd > 0) {
		write(logfd, linein, linelen);
		write(logfd, "\n" ,1);
	}

	return r * 10 + q;
syntax:
	/* if this fails we're already in bad trouble */
	(void) write(1, "Zsyntax error in server reply\n", 31);
	quit();
}

/**
 * check the reply of the server
 *
 * @param status status codes to print or NULL if not to
 * @param pre text to write to stdout before server reply if mask matches
 * @param mask bitmask for pre: 1: 2xx, 2: 4xx, 4: 5xx
 * @return the SMTP result code
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
			m = 4;
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
 * greet the server, try ehlo and fall back to helo if needed
 *
 * @return 0 if greeting succeeded, 1 on error
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
						int r;

						r = extensions[j].func();
						if (!r) {
							smtpext |= (1 << j);
							break;
/*						} else if (r < 0) {
							return r;
*/						} else {
							const char *logmsg[4] = {"syntax error in EHLO response \"",
									    extensions[j].name,
									    "\"", NULL};

							log_writen(LOG_WARNING, logmsg);
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

void
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

static char ipname[16];

static void
makelog(const char *ext)
{
	char fn[30];

	if (logfd)
		close(logfd);
	memcpy(fn, ipname, strlen(ipname));
	memcpy(fn + strlen(ipname), ext, strlen(ext) + 1);
	logfd = open(fn, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (logfd == -1) {
		if (strcmp(ext, "conn")) {
			write(2, "can not create ", 15);
			write(2, fn, strlen(fn));
			write(2, "\n", 1);
			quit();
		} else
			exit(1);
	}
}

int
main(int argc, char *argv[])
{
	int i;
	struct ips *mx = NULL;

	setup();

	if (argc == 0) {
		write(2, "Usage: Qsurvey hostname\n", 24);
		exit(EINVAL);
	}

	ipname[0] = '\0';
	getmxlist(argv[1], &mx);
	sortmx(&mx);

	if (!mx->next && IN6_IS_ADDR_V4MAPPED(&(mx->addr)))
		goto work;

	while (mx) {
		while (mx && !IN6_IS_ADDR_V4MAPPED(&(mx->addr))) {
			mx = mx->next;
		}

		if (!mx)
			exit(0);

		switch (fork()) {
			case -1:	i = errno;
					write(2, "unable to fork\n", 15);
					exit(i);
			case 0:		goto work;
		}

		mx = mx->next;
	}

work:
	if (!mx)
		exit(0);
	chdir("/tmp/Qsurvey");
	memset(ipname, 0, sizeof(ipname));
	for (i = 12; i <= 14; i++) {
		ultostr(mx->addr.s6_addr[i], ipname + strlen(ipname));
		if (i == mkdir(ipname, S_IRUSR | S_IWUSR | S_IXUSR)) {
			if (errno != EEXIST) {
				write(2, "cannot create directory ", 24);
				write(2, ipname, strlen(ipname));
				write(2, "\n", 1);
			}
		}
		ipname[strlen(ipname)] = '/';
	}
	ultostr(mx->addr.s6_addr[15], ipname + strlen(ipname));
	ipname[strlen(ipname)] = '-';

	makelog("conn");

	tryconn(mx, &in6addr_any);
	close(0);
	dup2(socketd, 0);
	if (netget() != 220)
		quit();

	/* AOL and others */
	while (linein[3] == '-')
		netget();

	makelog("ehlo");

	if (greeting())
		quit();

	getrhost(mx);
	freeips(mx);

	if (smtpext & 0x04) {
		makelog("tls-init");
		if (tls_init()) {
			makelog("tls-ehlo");
			if (greeting()) {
				write(2, "EHLO failed after STARTTLS\n", 28);
				quit();
			}
		}
	}

	makelog("vrfy");
	netwrite("VRFY postmaster\r\n");
	do {
		netget();
	} while (linein[3] == '-');
	makelog("noop");
	netwrite("NOOP\r\n");
	do {
		netget();
	} while (linein[3] == '-');
	makelog("rset");
	netwrite("RSET\r\n");
	do {
		netget();
	} while (linein[3] == '-');
	makelog("help");
	netwrite("HELP\r\n");
	do {
		netget();
	} while (linein[3] == '-');
	quit();
}
