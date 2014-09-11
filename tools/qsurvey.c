/** \file qsurvey.c
 \brief main functions of Qsurvey

 This file contains the main functions of Qsurvey, a simple SMTP server survey
 to check for remote SMTP server capabilities and software version.
 */

#include <control.h>
#include <diropen.h>
#include <fmt.h>
#include <log.h>
#include <match.h>
#include <netio.h>
#include <qdns.h>
#include <qmaildir.h>
#include <qremote/client.h>
#include <qremote/conn.h>
#include <qremote/greeting.h>
#include <qremote/qremote.h>
#include <qremote/starttlsr.h>
#include <sstring.h>
#include <tls.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

int socketd;
string heloname;
unsigned int smtpext;
char *rhost;
size_t rhostlen;
char *partner_fqdn;
unsigned long remotesize;
static int logfd;
static int logdirfd = -1;
static struct ips *mx;
static struct in6_addr outip;
static struct in6_addr outip6;

void
err_mem(const int doquit)
{
	/* write text including 0 byte */
	write_status("Z4.3.0 Out of memory.");
	net_conn_shutdown(doquit ? shutdown_clean : shutdown_abort);
}

void
err_confn(const char **errmsg, void *freebuf)
{
	log_writen(LOG_ERR, errmsg);
	free(freebuf);
	/* write text including 0 byte */
	write_status("Z4.3.0 Configuration error.");
	net_conn_shutdown(shutdown_abort);
}

void
err_conf(const char *errmsg)
{
	const char *msg[] = {errmsg, NULL};
	err_confn(msg, NULL);
}

void
net_conn_shutdown(const enum conn_shutdown_type sd_type)
{
	if ((sd_type == shutdown_clean) && (socketd >= 0)) {
		quitmsg();
	} else if (socketd >= 0) {
		close(socketd);
		socketd = -1;
		if (ssl) {
			ssl_free(ssl);
			ssl = NULL;
		}
	}

	freeips(mx);
	free(heloname.s);
	if (logdirfd >= 0)
		close(logdirfd);

	exit(0);
}

/*
 * private version: ignore all configured smtproutes since this tool will not
 * really deliver any mail.
 */
struct ips *
smtproute(const char *remhost __attribute__((unused)), const size_t reml __attribute__((unused)), unsigned int *port __attribute__((unused)))
{
	errno = 0;
	return NULL;
}

static void
setup(void)
{
	int j;
	unsigned long tmp;
	char *ipbuf;

#undef USESYSLOG

	if (chdir(AUTOQMAIL))
		err_conf("cannot chdir to qmail directory");

	controldir_fd = get_dirfd(-1, AUTOQMAIL "/control");
	if (controldir_fd < 0)
		err_conf("cannot get a file descriptor for " AUTOQMAIL "/control");

	if ( (j = loadoneliner(controldir_fd, "helohost", &heloname.s, 1) ) < 0 ) {
		if ( ( j = loadoneliner(controldir_fd, "me", &heloname.s, 0) ) < 0 ) {
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
	if ( (j = loadintfd(openat(controldir_fd, "timeoutremote", O_RDONLY | O_CLOEXEC), &tmp, 320)) < 0) {
		err_conf("parse error in control/timeoutremote");
	}
	timeout = tmp;

	if (((ssize_t)loadoneliner(controldir_fd, "outgoingip", &ipbuf, 1)) >= 0) {
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
	if (((ssize_t)loadoneliner(controldir_fd, "outgoingip6", &ipbuf, 1)) >= 0) {
		int r = inet_pton(AF_INET6, ipbuf, &outip6);

		free(ipbuf);
		if (r <= 0)
			err_conf("parse error in control/outgoingip6");

		if (IN6_IS_ADDR_V4MAPPED(&outip6))
			err_conf("control/outgoingip6 has IPv4 address");
	} else
#endif
		outip6 = in6addr_any;

	heloname.len = j;

}

void
quitmsg(void)
{
	netwrite("QUIT\r\n");
	do {
/* don't care about what he replies: we want to quit, if he don't want us to he must pay money *eg* */
		if (net_read(0)) {
			log_write(LOG_ERR, "network read error while waiting for QUIT reply");
			break;
		}
	} while ((linein.len >= 4) && (linein.s[3] == '-'));
	if (ssl) {
		ssl_free(ssl);
		ssl = NULL;
	}
	close(socketd);
	socketd = -1;
}

/**
 * get one line from the network, handle all error cases
 *
 * @return SMTP return code of the message
 */
int
netget(const unsigned int terminate __attribute__ ((unused)))
{
	int q, r;

	if (net_read(1)) {
		switch (errno) {
		case ENOMEM:	err_mem(1);
		case EINVAL:
		case E2BIG:	goto syntax;
		default:
			{
				const char *tmp[] = { "Z4.3.0 ", strerror(errno) };

				write_status_m(tmp, 2);
				net_conn_shutdown(shutdown_clean);
			}
		}
	}
	if (linein.len < 3)
		goto syntax;
	if ((linein.len > 3) && ((linein.s[3] != ' ') && (linein.s[3] != '-')))
		goto syntax;
	r = linein.s[0] - '0';
	if ((r < 2) || (r > 5))
		goto syntax;
	q = linein.s[1] - '0';
	if ((q < 0) || (q > 9))
		goto syntax;
	r = r * 10 + q;
	q = linein.s[2] - '0';
	if ((q < 0) || (q > 9))
		goto syntax;

	if (logfd > 0) {
		write(logfd, linein.s, linein.len);
		write(logfd, "\n" ,1);
	}

	return r * 10 + q;
syntax:
	/* if this fails we're already in bad trouble */
	write_status("Z5.5.2 syntax error in server reply");
	net_conn_shutdown(shutdown_clean);
}

void
dieerror(int error)
{
	switch (error) {
	case ETIMEDOUT:
		write_status("Z4.4.1 connection to remote server died");
		log_write(LOG_WARNING, "connection timed out");
		break;
	case ECONNRESET:
		write_status("Z4.4.1 connection to remote timed out");
		log_write(LOG_WARNING, "connection died");
		break;
	}
	net_conn_shutdown(shutdown_abort);
}

static void
makelog(const char *ext)
{
	if (logfd)
		close(logfd);
	logfd = openat(logdirfd, ext, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
	if (logfd == -1) {
		if (strcmp(ext, "conn")) {
			write(2, "can not create ", 15);
			write(2, ext, strlen(ext));
			write(2, "\n", 1);
			net_conn_shutdown(shutdown_clean);
		} else {
			net_conn_shutdown(shutdown_abort);
		}
	}
}

/**
 * @brief create a directory tree
 * @param pattern the dot-separated pattern to use
 * @return fd of the last directory created
 *
 * Given a pattern of foo.bar it will create the directories foo/ and foo/bar.
 * It is no error if they already exist. If creation fails the process is
 * terminated.
 */
static int
mkdir_pr(const char *pattern)
{
	char fnbuf[PATH_MAX];
	const char *end;
	const char *start;
	int r;
	int dirfd = dup(logdirfd);

	if (dirfd < 0) {
		fprintf(stderr, "cannot open current directory: %s\n",
			strerror(errno));
		exit(1);
	}

	end = pattern + strlen(pattern);
	start = strrchr(pattern, '.');

	if (start == NULL)
		start = pattern;

	while (start != pattern) {
		const size_t len = end - start - 1;
		int nextdir;
		strncpy(fnbuf, start + 1, end - start - 1);
		fnbuf[len] = '\0';
		r = mkdirat(dirfd, fnbuf, 0755);

		if ((r < 0) && (errno != EEXIST)) {
			fprintf(stderr, "cannot create %s: %s\n",
					fnbuf, strerror(errno));
			exit(1);
		}

		nextdir = openat(dirfd, fnbuf, O_RDONLY | O_CLOEXEC);
		if (nextdir < 0) {
			fprintf(stderr, "cannot open %s: %s\n",
					fnbuf, strerror(errno));
			close(dirfd);
			exit(1);
		}
		close(dirfd);
		dirfd = nextdir;

		end = start;
		start--;
		while ((start != pattern) && (*start != '.'))
			start--;
	}

	strncpy(fnbuf, pattern, end - pattern);
	fnbuf[end - pattern] = '\0';

	r = mkdirat(dirfd, fnbuf, 0755);
	if ((r < 0) && (errno != EEXIST)) {
		fprintf(stderr, "cannot create %s: %s\n",
				fnbuf, strerror(errno));
		close(dirfd);
		exit(1);
	}

	r = openat(dirfd, fnbuf, O_RDONLY | O_CLOEXEC);
	if (r < 0) {
		fprintf(stderr, "cannot open %s: %s\n",
				fnbuf, strerror(errno));
		close(dirfd);
		exit(1);
	}
	close(dirfd);

	return r;
}

int
main(int argc, char *argv[])
{
	char iplinkname[PATH_MAX];
	char ipname[64]; /* enough for "1122/3344/5566/7788/99aa/bbcc/ddee/ff00/\0" */
	const char *logdir = getenv("QSURVEY_LOGDIR");
	struct ips *cur;
	int i;
	int dirfd;
	unsigned short s;

	if (argc != 2) {
		write(2, "Usage: Qsurvey hostname\n", 24);
		return EINVAL;
	}

	setup();

	getmxlist(argv[1], &mx);
	sortmx(&mx);

#ifdef IPV4ONLY
	/* if no IPv4 address is available just exit */
	if (mx->priority > 65536) {
		freeips(mx);
		return 0;
	}
#endif

	/* only one address is available: just do it in this
	 * process, no need to fork. */
	cur = mx;
	s = 0;
	if (((mx->next == NULL) || (mx->next->priority > 65536)) && (mx->count == 1))
		goto work;

	FOREACH_STRUCT_IPS(cur, s, mx) {
		if (cur->priority > 65536)
			break;

		switch (fork()) {
		case -1:
			i = errno;
			write(2, "unable to fork\n", 15);
			freeips(mx);
			return i;
		case 0:
			break;
		default:
			continue;
		}

		/* case 0, i.e. new child */
		break;
	}

	freeips(mx);
	return 0;
work:
	if (logdir == NULL)
		logdir = "/tmp/Qsurvey";

	logdirfd = open(logdir, O_RDONLY | O_CLOEXEC);

	if (logdirfd < 0) {
		fprintf(stderr, "cannot open log directory %s: %s\n",
				logdir, strerror(errno));
		freeips(mx);
		return 1;
	}

	dirfd = mkdir_pr(argv[1]);

	memset(ipname, 0, sizeof(ipname));
	if (IN6_IS_ADDR_V4MAPPED(cur->addr + s)) {
		for (i = 12; i <= 15; i++) {
			char append[5];
			sprintf(append, "%u/", cur->addr[s].s6_addr[i]);
			strcat(ipname, append);
			if ((mkdirat(logdirfd, ipname, S_IRUSR | S_IWUSR | S_IXUSR) < 0) && (errno != EEXIST)) {
				fprintf(stderr, "cannot create directory %s: %s\n", ipname, strerror(errno));
				close(dirfd);
				net_conn_shutdown(shutdown_abort);
			}
		}
	} else {
		for (i = 0; i < 8; i++) {
			char append[6];
			sprintf(append, "%04x/", ntohs(cur->addr[s].s6_addr16[i]));
			strcat(ipname, append);
			if ((mkdirat(logdirfd, ipname, S_IRUSR | S_IWUSR | S_IXUSR) < 0) && (errno != EEXIST)) {
				fprintf(stderr, "cannot create directory %s: %s\n", ipname, strerror(errno));
				close(logdirfd);
				net_conn_shutdown(shutdown_abort);
			}
		}
	}
	i = openat(logdirfd, ipname, O_RDONLY | O_CLOEXEC);
	if (i < 0) {
		fprintf(stderr, "cannot open IP directory %s: %s\n",
				ipname, strerror(errno));
		close(logdirfd);
		close(dirfd);
		net_conn_shutdown(shutdown_abort);
	}

	close(logdirfd);
	logdirfd = i;

	ipname[strlen(ipname) - 1] = '\0';
	sprintf(iplinkname, "%s/%s", logdir, ipname);

	if (IN6_IS_ADDR_V4MAPPED(cur->addr + s))
		inet_ntop(AF_INET, cur->addr[s].s6_addr32 + 3, ipname, sizeof(ipname));
	else
		inet_ntop(AF_INET6, cur->addr + s, ipname, sizeof(ipname));
	symlinkat(iplinkname, dirfd, ipname);

	makelog("conn");

	socketd = tryconn(cur, &outip, &outip6);
	if (socketd < 0) {
		fprintf(stderr, "can't connect to any server\n");
		close(logdirfd);
		close(dirfd);
		net_conn_shutdown(shutdown_abort);
	}
	dup2(socketd, 0);
	if (netget(1) != 220)
		net_conn_shutdown(shutdown_clean);

	/* AOL and others */
	while (linein.s[3] == '-')
		netget(1);

	makelog("ehlo");

	i = greeting();
	if (i < 0)
		net_conn_shutdown(shutdown_clean);
	smtpext = i;

	freeips(mx);
	mx = NULL;

	if (smtpext & esmtp_starttls) {
		makelog("tls-init");
		if (tls_init() != 0) {
			net_conn_shutdown(shutdown_clean);
		} else {
			X509 *x509 = SSL_get_peer_certificate(ssl);

			if (x509 != NULL) {
				makelog("server.pem");
				FILE *f = fdopen(logfd, "w");

				if (f != NULL) {
					PEM_write_X509(f, x509);
					fclose(f);
				}

				X509_free(x509);
			}

			makelog("tls-ehlo");
			if (greeting()) {
				write(2, "EHLO failed after STARTTLS\n", 28);
				net_conn_shutdown(shutdown_clean);
			}
		}
	}

	makelog("vrfy");
	netwrite("VRFY postmaster\r\n");
	do {
		netget(1);
	} while (linein.s[3] == '-');
	makelog("noop");
	netwrite("NOOP\r\n");
	do {
		netget(1);
	} while (linein.s[3] == '-');
	makelog("rset");
	netwrite("RSET\r\n");
	do {
		netget(1);
	} while (linein.s[3] == '-');
	makelog("help");
	netwrite("HELP\r\n");
	do {
		netget(1);
	} while (linein.s[3] == '-');
	net_conn_shutdown(shutdown_clean);
}
