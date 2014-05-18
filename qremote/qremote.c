/** \file qremote.c
 \brief main functions of Qremote

 This file contains the main function, the configuration and error handling of Qremote,
 the drop-in replacement for qmail-remote.
 */
#include <qremote/qremote.h>

#include <qremote/conn.h>
#include <qremote/client.h>
#include <qremote/starttlsr.h>
#include <qremote/qrdata.h>

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
#include <qremote/greeting.h>
#include "netio.h"
#include "qdns.h"
#include "control.h"
#include "log.h"
#include "sstring.h"
#include "fmt.h"
#include "ipme.h"
#include "tls.h"
#include "qmaildir.h"

int socketd = -1;
string heloname;
unsigned int smtpext;	/**< the SMTP extensions supported by the remote server */
char *rhost;		/**< the DNS name (if present) and IP address of the remote server to be used in log messages */
size_t rhostlen;	/**< valid length of rhost */
char *partner_fqdn;	/**< the DNS name of the remote server, or NULL if no reverse lookup exists */
static struct in6_addr outip;
static struct in6_addr outip6;

void
write_status(const char *str)
{
	(void) write(1, str, strlen(str) + 1);
}

void
write_status_m(const char **strs, const unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count - 1; i++)
		(void) write(1, strs[i], strlen(strs[i]));
	write_status(strs[count - 1]);
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
net_conn_shutdown(const enum conn_shutdown_type sd_type)
{
	if ((sd_type == shutdown_clean) && (socketd >= 0)) {
		quitmsg();
	} else if (socketd >= 0) {
		close(socketd);
		socketd = -1;
	}

	if (ssl != NULL) {
		ssl_free(ssl);
		ssl = NULL;
	}

#ifdef USESYSLOG
	closelog();
#endif

	free(heloname.s);
	free(partner_fqdn);
	free(rhost);

	exit(0);
}

void
err_mem(const int doquit)
{
	write_status("Z4.3.0 Out of memory.\n");

	net_conn_shutdown(doquit ? shutdown_clean : shutdown_abort);
}

void
err_conf(const char *errmsg)
{
	const char *msg[] = {errmsg, NULL};
	err_confn(msg, NULL);
}

/**
 * @brief log a configuration error and exit
 * @param errmsg array of strings to combine to the message to log
 * @param freebuf a pointer to a buffer passed to free() after logging
 *
 * Use freebuf if the contents of this buffer need to be part of errmsg.
 * If you do not have anything to free just pass NULL.
 */
void
err_confn(const char **errmsg, void *freebuf)
{
	log_writen(LOG_ERR, errmsg);
	free(freebuf);

	write_status("Z4.3.0 Configuration error.\n");
	net_conn_shutdown(shutdown_clean);
}

static void
setup(void)
{
	int j;
	unsigned long chunk;
	char *ipbuf;

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
	heloname.len = j;

	if (loadintfd(open("control/timeoutremote", O_RDONLY), &chunk, 320) < 0) {
		err_conf("parse error in control/timeoutremote");
	}
	timeout = chunk;

#ifdef CHUNKING
	if (loadintfd(open("control/chunksizeremote", O_RDONLY), &chunk, 32768) < 0) {
		err_conf("parse error in control/chunksizeremote");
	} else {
		if (chunk >= ((unsigned long)1 << 31)) {
			err_conf("chunksize in control/chunksizeremote too big");
		}
		chunksize = chunk & 0xffffffff;
	}
#endif

	if (((ssize_t)loadoneliner("control/outgoingip", &ipbuf, 1)) >= 0) {
		int r = inet_pton(AF_INET6, ipbuf, &outip);

		if (r <= 0) {
			struct in_addr a4;
			r = inet_pton(AF_INET, ipbuf, &a4);
			outip.s6_addr32[0] = 0;
			outip.s6_addr32[1] = 0;
			outip.s6_addr32[2] = htonl(0xffff);
			outip.s6_addr32[3] = a4.s_addr;
		}

		free(ipbuf);
		if (r <= 0)
			err_conf("parse error in control/outgoingip");

		if (!IN6_IS_ADDR_V4MAPPED(&outip))
			err_conf("compiled for IPv4 only but control/outgoingip has IPv6 address");
	} else {
		outip = in6addr_any;
	}

#ifndef IPV4ONLY
	if (((ssize_t)loadoneliner("control/outgoingip6", &ipbuf, 1)) >= 0) {
		int r = inet_pton(AF_INET6, ipbuf, &outip6);

		free(ipbuf);
		if (r <= 0)
			err_conf("parse error in control/outgoingip6");

		if (IN6_IS_ADDR_V4MAPPED(&outip6))
			err_conf("control/outgoingip6 has IPv4 address");
	} else
#endif
		outip6 = in6addr_any;

#ifdef DEBUG_IO
	j = open("control/Qremote_debug", O_RDONLY);
	do_debug_io = (j > 0);
	if (j > 0)
		close(j);
#endif
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
		case ENOMEM:
			err_mem(1);
		case EINVAL:
		case E2BIG:
			goto syntax;
		default:
			{
				const char *tmp[] = { "Z4.3.0 ", strerror(errno) };

				write_status_m(tmp, 2);
				net_conn_shutdown(shutdown_clean);;
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
	/* Even if 5.5.2 is a permanent error don't use 'D' return code here,
	 * hope that this is just a hiccup on the other side and will get
	 * fixed soon. */
	write_status("Z5.5.2 syntax error in server reply\n");
	net_conn_shutdown(shutdown_clean);;
}

/**
 * greet the server, try ehlo and fall back to helo if needed
 *
 * @return 0 if greeting succeeded, 1 on error
 */
static int
greeting(void)
{
	const char *cmd[3];
	int s;			/* SMTP status */

	cmd[0] = "EHLO ";
	cmd[1] = heloname.s;
	cmd[2] = NULL;
	net_writen(cmd);
	do {
		s = netget();
		if (s == 250) {
			int ext = esmtp_check_extension(linein + 4);

			if (ext < 0) {
				const char *logmsg[4] = {"syntax error in EHLO response \"",
						linein + 4, "\"", NULL};

				log_writen(LOG_WARNING, logmsg);
			} else {
				smtpext |= ext;
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
	const char *logmsg[] = { "connection to ", rhost, NULL, NULL };

	switch (error) {
	case ETIMEDOUT:
		write_status("Z4.4.1 connection to remote timed out\n");
		logmsg[2] = " timed out";
		log_writen(LOG_WARNING, logmsg);
		break;
	case ECONNRESET:
		write_status("Z4.4.1 connection to remote server died\n");
		logmsg[2] = " died";
		log_writen(LOG_WARNING, logmsg);
		break;
	}
	net_conn_shutdown(shutdown_abort);
}

static const char *mailerrmsg[] = {"Connected to ", NULL, " but sender was rejected", NULL};

int
main(int argc, char *argv[])
{
	const char *netmsg[10];
	int rcptstat = 1;	/* this means: all recipients have been rejected */
	struct ips *mx = NULL;
	int rcptcount = argc - 3;
	struct stat st;
	char sizebuf[ULSTRLEN];
	unsigned int lastmsg;	/* last message in array */
	unsigned int recodeflag;

	setup();

	if (rcptcount <= 0) {
		log_write(LOG_CRIT, "too few arguments");
		write_status("Z4.3.0 internal error: Qremote called with invalid arguments\n");
		net_conn_shutdown(shutdown_abort);
	}

	getmxlist(argv[1], &mx);
	if (targetport == 25) {
		mx = filter_my_ips(mx);
		if (mx == NULL) {
			const char *msg[] = { "Z4.4.3 all mail exchangers for ",
					argv[1], " point back to me\n" };
			write_status_m(msg, 3);
			net_conn_shutdown(shutdown_abort);
		}
	}
	sortmx(&mx);

	/* this shouldn't fail normally: qmail-rspawn did it before successfully */
	if (fstat(0, &st)) {
		if (errno == ENOMEM)
			err_mem(0);
		log_write(LOG_CRIT, "can't fstat() input");
		write_status("Z4.3.0 internal error: can't fstat() input\n");
		freeips(mx);
		net_conn_shutdown(shutdown_abort);
	}
	msgsize = st.st_size;
	msgdata = mmap(NULL, msgsize, PROT_READ, MAP_SHARED, 0, 0);

	if (msgdata == MAP_FAILED) {
		log_write(LOG_CRIT, "can't mmap() input");
		write_status("Z4.3.0 internal error: can't mmap() input\n");
		freeips(mx);
		net_conn_shutdown(shutdown_abort);
	}
	dup2(0, 42);

/* for all MX entries we got: try to enable connection, check if the SMTP server wants us
 * (sends 220 response) and EHLO/HELO succeeds. If not, try next. If none left, exit. */
	do {
		int flagerr = 0;

		if (socketd >= 0)
			while ((close(socketd) < 0) && (errno == EINTR));
		socketd = tryconn(mx, &outip, &outip6);
		dup2(socketd, 0);
		if (netget() != 220) {
			quitmsg();
			continue;
		}
		while (strncmp("220-", linein, 4) == 0) {
			if (net_read() == 0)
				continue;

			flagerr = 1;
			switch (errno) {
			case ENOMEM:
					err_mem(1);
			case EINVAL:
			case E2BIG:
					write_status("Z5.5.2 syntax error in server reply\n");
					quitmsg();
					break;
			default:
				{
					const char *tmp[] = { "Z4.3.0 ", strerror(errno) };

					write_status_m(tmp, 2);
					quitmsg();
				}
			}
		}
		if (flagerr)
			continue;

		if (strncmp("220 ", linein, 4)) {
			const char *dropmsg[] = {"invalid greeting from ", NULL, NULL};

			getrhost(mx);
			dropmsg[1] = rhost;
			log_writen(LOG_WARNING, dropmsg);
			quitmsg();
		}
	} while ((socketd < 0) || greeting());

	getrhost(mx);
	freeips(mx);
	mailerrmsg[1] = rhost;

	if (smtpext & esmtp_starttls) {
		if (tls_init()) {
			if (greeting()) {
				write_status("ZEHLO failed after STARTTLS\n");
				net_conn_shutdown(shutdown_clean);;
			}
			successmsg[4] = " encrypted";
		}
	}

/* check if message is plain ASCII or not */
	recodeflag = need_recode(msgdata, msgsize);

	netmsg[0] = "MAIL FROM:<";
	netmsg[1] = argv[2];
	lastmsg = 2;
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
		int i;

/* server allows PIPELINING: first send all the messages, then check the replies.
 * This allows to hide network latency. */
		/* batch the first recipient with the from */
		netmsg[lastmsg++] = "\r\nRCPT TO:<";
		netmsg[lastmsg++] = argv[3];
		netmsg[lastmsg++] = ">\r\n";
		netmsg[lastmsg] = NULL;
		net_write_multiline(netmsg);

		lastmsg = 1;
		netmsg[0] = "RCPT TO:<";
		for (i = 4; i < argc; i++) {
			netmsg[lastmsg++] = argv[i];
			if ((i == argc - 1) || ((i % 4) == 3)) {
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
			for (i = rcptcount; i > 0; i--)
				checkreply(NULL, NULL, 0);
			net_conn_shutdown(shutdown_clean);;
		}
/* RCPT TO: replies */
		for (i = rcptcount; i > 0; i--) {
			if (checkreply(" sh", NULL, 0) < 300) {
				write_status("r");
				rcptstat = 0;
			}
		}
		if (rcptstat)
			net_conn_shutdown(shutdown_clean);;
	} else {
		int i;

/* server does not allow pipelining: we must do this one by one */
		netmsg[lastmsg] = NULL;
		net_writen(netmsg);

		if (checkreply(" ZD", mailerrmsg, 6) >= 300)
			net_conn_shutdown(shutdown_clean);;

		netmsg[0] = "RCPT TO:<";
		netmsg[2] = ">";
		netmsg[3] = NULL;

		for (i = 3; i < argc; i++) {
			netmsg[1] = argv[i];
			net_writen(netmsg);
			if (checkreply(" sh", NULL, 0) < 300) {
				write_status("r");
				rcptstat = 0;
			}
		}
		if (rcptstat)
			net_conn_shutdown(shutdown_clean);;
	}
	successmsg[0] = rhost;
#ifdef CHUNKING
	if (smtpext & esmtp_chunking) {
		send_bdat(recodeflag);
	} else {
#else
	{
#endif
		send_data(recodeflag);
	}
	net_conn_shutdown(shutdown_clean);;
}
