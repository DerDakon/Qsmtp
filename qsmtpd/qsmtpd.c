/** \file qsmtpd.c
 \brief main part of Qsmtpd

 This file contains the main function and the basic commands of Qsmtpd
 SMTP server.
 */
#include <qsmtpd/qsmtpd.h>

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <dirent.h>
#include <signal.h>
#include <dirent.h>
#include <qsmtpd/addrparse.h>
#include <qsmtpd/vpop.h>
#include <qsmtpd/starttls.h>
#include <qsmtpd/syntax.h>
#include <qsmtpd/xtext.h>
#include <qsmtpd/antispam.h>
#include "log.h"
#include "netio.h"
#include "qdns.h"
#include "control.h"
#include <qsmtpd/userconf.h>
#include <qsmtpd/userfilters.h>
#include "tls.h"
#include "sstring.h"
#include "version.h"
#include "qdns.h"
#include <qsmtpd/qsauth.h>
#include <qsmtpd/qsdata.h>
#include "fmt.h"
#include "qmaildir.h"

int smtp_noop(void);
int smtp_quit(void);
int smtp_rset(void);
int smtp_helo(void);
int smtp_ehlo(void);
int smtp_from(void);
int smtp_rcpt(void);
/* int smtp_data(void); is declared in qsdata.h */
int smtp_vrfy(void);
int http_post(void);

#define _C(c,l,m,f,s,o) { .name = c, .len = l, .mask = m, .func = f, .state = s, .flags = o }

struct smtpcomm commands[] = {
	_C("NOOP",	 4, 0xffff, smtp_noop,     -1, 0),  /* 0x0001 */
	_C("QUIT",	 4, 0xfffd, smtp_quit,      0, 0),  /* 0x0002 */
	_C("RSET",	 4, 0xfffd, smtp_rset,    0x1, 0),  /* 0x0004 */ /* the status to change to is set in smtp_rset */
	_C("HELO",	 4, 0xfffd, smtp_helo,      0, 1),  /* 0x0008 */
	_C("EHLO",	 4, 0xfffd, smtp_ehlo,      0, 1),  /* 0x0010 */
	_C("MAIL FROM:",10, 0x0018, smtp_from,      0, 3),  /* 0x0020 */
	_C("RCPT TO:",	 8, 0x0060, smtp_rcpt,      0, 1),  /* 0x0040 */
	_C("DATA",	 4, 0x0040, smtp_data,   0x10, 0),  /* 0x0080 */ /* the status to change to is changed in smtp_data */
	_C("STARTTLS",	 8, 0x0010, smtp_starttls, 0x1, 0), /* 0x0100 */
	_C("AUTH",	 4, 0x0010, smtp_auth,     -1, 1),  /* 0x0200 */
	_C("VRFY",	 4, 0xffff, smtp_vrfy,     -1, 1),  /* 0x0400 */
#ifdef CHUNKING
	_C("BDAT",	 4, 0x0840, smtp_bdat,     -1, 1),  /* 0x0800 */ /* the status to change to is changed in smtp_bdat */
#endif
	_C("POST",	 4, 0xffff, http_post,     -1, 1)   /* 0x1000 */ /* this should stay last */
};

#undef _C

static unsigned int rcptcount;		/**< number of recipients in lists including rejected */
static char *gcbuf;			/**< buffer for globalconf array (see below) */

int relayclient;			/**< flag if this client is allowed to relay by IP: 0 unchecked, 1 allowed, 2 denied */
static char *rcpthosts;			/**< memory mapping of control/rcpthosts */
static off_t rcpthsize;			/**< sizeof("control/rcpthosts") */
unsigned long sslauth;			/**< if SMTP AUTH is only allowed after STARTTLS */
unsigned long databytes;		/**< maximum message size */
unsigned int goodrcpt;			/**< number of valid recipients */
int badbounce;				/**< bounce message with more than one recipient */
struct xmitstat xmitstat;		/**< This contains some flags describing the transmission and it's status. */
char *protocol;				/**< the protocol string to use (e.g. "ESMTP") */
const char **globalconf;		/**< contents of the global "filterconf" file (or NULL) */
string heloname;			/**< the fqdn to show in helo */
string msgidhost;			/**< the fqdn to use if a message-id is added */
string liphost;				/**< replacement domain if TO address is <foo@[ip]> */
int socketd = 1;			/**< the descriptor where messages to network are written to */
long comstate = 0x001;			/**< status of the command state machine, initialized to noop */
int authhide;				/**< hide source of authenticated mail */
int submission_mode;			/**< if we should act as message submission agent */
char certfilename[24 + INET6_ADDRSTRLEN] = "control/servercert.pem";		/**< path to SSL certificate filename */

struct recip *thisrecip;

#define MAXRCPT		500		/**< maximum number of recipients in a single mail */

/**
 * write error message for messages with empty MAIL FROM and multiple recipients
 */
static inline int
err_badbounce(void)
{
	tarpit();
	return netwrite("550 5.5.3 bounce messages must not have more than one recipient\r\n");
}

/**
 * \brief write and log error message if opening config file leads to an error
 *
 * @param fn name of the file that caused the error
 * @see err_control2
 */
int
err_control(const char *fn)
{
	const char *logmsg[] = {"error: unable to open file: \"", fn, "\"\n", NULL};

	log_writen(LOG_ERR, logmsg);
	return netwrite("421 4.3.5 unable to read controls\r\n");
}

/**
 * \brief write and log error message if opening config file leads to an error
 *
 * @param msg additional message to log
 * @param fn name of the file that caused the error
 * @see err_control
 */
static int
err_control2(const char *msg, const char *fn)
{
	const char *logmsg[] = {"error: unable to open file: ", msg, fn, "\n", NULL};

	log_writen(LOG_ERR, logmsg);
	return netwrite("421 4.3.5 unable to read controls\r\n");
}

/**
 * log error message and terminate program
 *
 * @param error error code that caused the program termination
 */
void
dieerror(int error)
{
	const char *logmsg[] = {"connection from [", xmitstat.remoteip, NULL, NULL};

	switch (error) {
	case ETIMEDOUT:
		logmsg[2] = "] timed out";
		break;
	case ECONNRESET:
		logmsg[2] = "] died";
		break;
	}
	log_writen(LOG_WARNING, logmsg);
	_exit(error);
}

static void
freeppol(void)
{
#ifdef PFIXPOLDIR
	while (pfixhead.tqh_first != NULL) {
		struct pfixpol *l = pfixhead.tqh_first;

		TAILQ_REMOVE(&pfixhead, pfixhead.tqh_first, entries);
		if (l->pid) {
			int res;

			close(l->fd);
			kill(l->pid, SIGTERM);
			if (!waitpid(l->pid, &res, WNOHANG)) {
				sleep(3);
				kill(l->pid, SIGKILL);
			}
		}
		free(l->name);
		free(l);
	}
#endif
}

/**
 * @brief check if the current client is authenticated
 * @return if the client may relay
 * @retval 1 the client may relay
 * @retval 0 the client is not permitted to relay
 * @retval <0 an error code
 */
static int
is_authenticated(void)
{
	if (is_authenticated_client())
		return 1;

	/* check if client is allowed to relay by IP */
	if (!relayclient) {
		int fd;
		const char *fn = connection_is_ipv4() ? "control/relayclients" : "control/relayclients6";

		relayclient = 2;
		if ( (fd = open(fn, O_RDONLY)) < 0) {
			if (errno != ENOENT) {
				return err_control(fn) ? -errno : -EDONE;
			}
		} else {
			int ipbl;

			if ((ipbl = lookupipbl(fd)) < 0) {
				const char *logmess[] = {"parse error in ", fn, NULL};

				/* reject everything on parse error, else this
				 * would turn into an open relay by accident */
				log_writen(LOG_ERR, logmess);
			} else if (ipbl) {
				relayclient = 1;
			}
		}
	}

	if (!(relayclient & 1)) {
		int i = tls_verify();
		if (i < 0)
			return i;

		relayclient = i ? 1 : relayclient;
	}

	return (relayclient == 1) ? 1 : 0;
}

static int
setup(void)
{
	int j;
	struct sigaction sa;
	struct stat st;
	char *tmp;
	unsigned long tl;
	char **tmpconf;
	int rcpthfd;		/* file descriptor of control/rcpthosts */
#ifdef PFIXPOLDIR
	DIR *dir;
#endif

#ifdef USESYSLOG
	openlog("Qsmtpd", LOG_PID, LOG_MAIL);
#endif

	/* make sure to have a reasonable default timeout if errors happen */
	timeout = 320;

	if (chdir(AUTOQMAIL)) {
		log_write(LOG_ERR, "cannot chdir to qmail directory");
		return EINVAL;
	}

#ifdef DEBUG_IO
	tmp = getenv("QSMTPD_DEBUG");
	if ((tmp != NULL) && (*tmp != '\0')) {
		do_debug_io = 1;
	} else {
		j = open("control/Qsmtpd_debug", O_RDONLY);
		do_debug_io = (j > 0);
		if (j > 0)
			close(j);
	}
#endif

	if ( (j = loadoneliner("control/me", &heloname.s, 0)) < 0)
		return errno;
	heloname.len = j;
	if (domainvalid(heloname.s)) {
		log_write(LOG_ERR, "control/me contains invalid name");
		return EINVAL;
	}

	j = loadoneliner("control/msgidhost", &msgidhost.s, 1);
	if (j < 0) {
		msgidhost.s = strdup(heloname.s);
		if (msgidhost.s == NULL)
			return ENOMEM;
		msgidhost.len = heloname.len;
	} else {
		msgidhost.len = j;
		if (domainvalid(msgidhost.s)) {
			log_write(LOG_ERR, "control/msgidhost contains invalid name");
			return EINVAL;
		}
	}

	if (( (j = loadoneliner("control/localiphost", &liphost.s, 1)) < 0) && (errno != ENOENT))
		return errno;
	if (j > 0) {
		liphost.len = j;
		if (domainvalid(liphost.s)) {
			log_write(LOG_ERR, "control/localiphost contains invalid name");
			return EINVAL;
		}
	} else {
		liphost.s = heloname.s;
		liphost.len = heloname.len;
	}

	rcpthfd = open("control/rcpthosts", O_RDONLY);
	if (rcpthfd < 0) {
		if (errno != ENOENT) {
			log_write(LOG_ERR, "control/rcpthosts not found");
			return errno;
		}
	} else {
		int e;
		while (flock(rcpthfd, LOCK_SH | LOCK_NB)) {
			if (errno != EINTR) {
				while (close(rcpthfd) && (errno == EINTR));
				log_write(LOG_WARNING, "cannot lock control/rcpthosts");
				return ENOLCK; /* not the right error code, but good enough */
			}
		}
		if (fstat(rcpthfd, &st)) {
			while (close(rcpthfd) && (errno == EINTR));
			log_write(LOG_ERR, "cannot fstat() control/rcpthosts");
			return errno;
		}
		if (st.st_size < 4) {
			while (close(rcpthfd) && (errno == EINTR));
			/* minimum length of domain name: x.yy = 4 bytes */
			log_write(LOG_ERR, "control/rcpthosts too short");
			return 1;
		}
		rcpthosts = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, rcpthfd, 0);
		e = errno;
		while (close(rcpthfd) && (errno == EINTR));
		if (rcpthosts == MAP_FAILED) {
			log_write(LOG_ERR, "cannot mmap() control/rcpthosts");
			errno = e;
			rcpthosts = NULL;
			return -1;
		}
		rcpthsize = st.st_size;
	}

#ifdef IPV4ONLY
	tmp = getenv("TCPLOCALIP");
	if (!tmp || !*tmp) {
		log_write(LOG_ERR, "can't figure out local IP (TCPLOCALIP not set)");
		return 1;
	}
	strncpy(xmitstat.remoteip, "::ffff:", sizeof(xmitstat.remoteip));
	strncat(xmitstat.remoteip + strlen("::ffff:"), tmp, sizeof(xmitstat.remoteip) - strlen("::ffff:") - 1);
	if (inet_pton(AF_INET6, xmitstat.remoteip, &xmitstat.slocalip) <= 0) {
		log_write(LOG_ERR, "can't figure out local IP (parse error)");
		return 1;
	}
	strcpy(xmitstat.localip, tmp);

	tmp = getenv("TCPREMOTEIP");
	if (!tmp || !*tmp) {
		log_write(LOG_ERR, "can't figure out IP of remote host (TCPREMOTEIP not set)");
		return 1;
	}
	xmitstat.remoteip[strlen("::ffff:")] = '\0';
	strncat(xmitstat.remoteip + strlen("::ffff:"), tmp, sizeof(xmitstat.remoteip) - strlen("::ffff:") - 1);
	if (inet_pton(AF_INET6, xmitstat.remoteip, &xmitstat.sremoteip) <= 0) {
		log_write(LOG_ERR, "can't figure out IP of remote host (parse error)");
		return 1;
	}
#else /* IPV4ONLY */
	tmp = getenv("TCP6LOCALIP");
	if (!tmp || !*tmp || (inet_pton(AF_INET6, tmp, &xmitstat.slocalip) <= 0)) {
		log_write(LOG_ERR, "can't figure out local IP");
		return 1;
	}
	if (IN6_IS_ADDR_V4MAPPED(&xmitstat.slocalip)) {
		memcpy(xmitstat.localip, tmp + 7, strlen(tmp + 7));
	} else {
		memcpy(xmitstat.localip, tmp, strlen(tmp));
	}

	tmp = getenv("TCP6REMOTEIP");
	if (!tmp || !*tmp || (inet_pton(AF_INET6, tmp, &xmitstat.sremoteip) <= 0)) {
		log_write(LOG_ERR, "can't figure out IP of remote host");
		return 1;
	}
	memcpy(xmitstat.remoteip, tmp, strlen(tmp));
#endif /* IPV4ONLY */

	/* RfC 2821, section 4.5.3.2: "Timeouts"
	 * An SMTP server SHOULD have a timeout of at least 5 minutes while it
	 * is awaiting the next command from the sender. */
	if ( (j = loadintfd(open("control/timeoutsmtpd", O_RDONLY), &tl, 320)) ) {
		int e = errno;
		log_write(LOG_ERR, "parse error in control/timeoutsmtpd");
		return e;
	}
	timeout = tl;
	if ( (j = loadintfd(open("control/databytes", O_RDONLY), &databytes, 0)) ) {
		int e = errno;
		log_write(LOG_ERR, "parse error in control/databytes");
		return e;
	}
	if (databytes) {
		maxbytes = databytes;
	} else {
		maxbytes = -1UL - 1000;
	}
	if ( (j = loadintfd(open("control/authhide", O_RDONLY), &tl, 0)) ) {
		log_write(LOG_ERR, "parse error in control/authhide");
		authhide = 0;
	} else {
		authhide = tl ? 1 : 0;
	}

	if ( (j = loadintfd(open("control/forcesslauth", O_RDONLY), &sslauth, 0)) ) {
		int e = errno;
		log_write(LOG_ERR, "parse error in control/forcesslauth");
		return e;
	}

	if ( (j = loadlistfd(open("control/filterconf", O_RDONLY), &gcbuf, &tmpconf, NULL)) ) {
		if ((errno == ENOENT) || !gcbuf) {
			gcbuf = NULL;
			tmpconf = NULL;
		} else {
			log_write(LOG_ERR, "error opening control/filterconf");
			return errno;
		}
	}
	globalconf = (const char **)tmpconf;

	j = userbackend_init();
	if (j != 0)
		return j;

#ifdef PFIXPOLDIR
	dir = opendir(PFIXPOLDIR);
	TAILQ_INIT(&pfixhead);
	if (dir) {
		struct dirent *de;

		/* read all entries in the directory. End on EOVERFLOW or end of list */
		while ( (de = readdir(dir)) ) {
			struct pfixpol *pf;
			if (de->d_name[0] == '.')
				continue;
			if (strlen(de->d_name) > 88) {
				const char *emsg[] = {"name of policy daemon too long, ignoring \"", de->d_name, "\"", NULL};
				log_writen(LOG_WARNING, emsg);
				continue;
			}

			pf = malloc(sizeof(*pf));
			if (pf)
				pf->name = malloc(strlen(de->d_name) + 1);

			if (!pf || !pf->name) {
				closedir(dir);
				freeppol();
				free(pf);
				return ENOMEM;
			}

			memcpy(pf->name, de->d_name, strlen(de->d_name));
			pf->name[strlen(de->d_name)] = '\0';

			log_write(LOG_DEBUG, pf->name);
			pf->pid = 0;
			TAILQ_INSERT_TAIL(&pfixhead, pf, entries);
		}
		closedir(dir);
	} else if (errno != ENOENT) {
	}
#endif

	/* block sigpipe. If we don't we can't handle the errors in smtp_data() correctly and remote host
	 * will see a connection drop on error (which is bad and violates RfC) */
	sa.sa_handler = SIG_IGN;
	j = sigaction(SIGPIPE, &sa, NULL);
	relayclient = 0;

	return j;
}

/** initialize variables related to this connection */
static int
connsetup(void)
{
	int j;

#ifdef IPV4ONLY
	xmitstat.ipv4conn = 1;
#else /* IPV4ONLY */
	xmitstat.ipv4conn = IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip) ? 1 : 0;
#endif /* IPV4ONLY */

	j = ask_dnsname(&xmitstat.sremoteip, &xmitstat.remotehost.s);
	if (j == -1) {
		log_write(LOG_ERR, "can't look up remote host name");
		return -1;
	} else if (j <= 0) {
		STREMPTY(xmitstat.remotehost);
	} else {
		xmitstat.remotehost.len = strlen(xmitstat.remotehost.s);
	}
	xmitstat.remoteinfo = getenv("TCPREMOTEINFO");
	xmitstat.remoteport = getenv("TCPREMOTEPORT");
	if (!xmitstat.remoteport || !*xmitstat.remoteport) {
		log_write(LOG_ERR, "can't figure out port of remote host (TCPREMOTEPORT not set)");
		xmitstat.remoteport = NULL;
	}

	return 0;
}

/**
 * \brief free all ressources allocated for mail transaction
 */
void
freedata(void)
{
	free(xmitstat.mailfrom.s);
	STREMPTY(xmitstat.mailfrom);
	freeips(xmitstat.frommx);
	xmitstat.frommx = NULL;
	free(xmitstat.tlsclient);
	xmitstat.tlsclient = NULL;
	while (head.tqh_first != NULL) {
		struct recip *l = head.tqh_first;

		TAILQ_REMOVE(&head, head.tqh_first, entries);
		free(l->to.s);
		free(l);
	}
	rcptcount = 0;
	goodrcpt = 0;
	badbounce = 0;
}

/**
 * \brief fork() but clean up internal structures
 *
 * This will work exactly like fork(). If it returns 0 (i.e. you are the
 * child) it will also clean the memory mappings etc. of the Qsmtpd process
 * that the child doesn't need.
 */
pid_t
fork_clean()
{
	pid_t ret = fork();

	if (ret != 0)
		return ret;

	munmap(rcpthosts, rcpthsize);

	return 0;
}

static int helovalid(const char *helo, const size_t len) __attribute__ ((nonnull (1)));

/**
 * check if the argument given to HELO/EHLO is syntactically correct
 *
 * @param helo helo to check
 * @return 0 on successful call, -1 on error
 * @retval 0 check was completed (xmitstat.helostatus was updated)
 * @retval -1 an error occured (usually ENOMEM)
 *
 * the status of the helo string ist stored in xmitstat.helostatus
 *
 * The values xmitstat.helostatus is set to:
 *  1: helo is my name
 *  2: helo is my IP address
 *  3: helo is syntactically invalid
 *  4: currently undefined
 *  5: 2+3 (helo is my IP address, but not enclosed in '[]')
 *  6, 7: currently undefined
 */
int
helovalid(const char *helo, const size_t len)
{
	char *s;
	int rc;

	xmitstat.helostatus = 0;
	free(xmitstat.helostr.s);

	/* We have the length of both strings anyway so we might be able to see
	 * the difference without looking at every single character in them */
	if (xmitstat.remotehost.len == len) {
		/* HELO is identical to reverse lookup: valid */
		if (!strcasecmp(helo, xmitstat.remotehost.s)) {
			STREMPTY(xmitstat.helostr);
			return 0;
		}
	}

	if ( (rc = newstr(&xmitstat.helostr, len + 1)) )
		return rc;
	/* +5-4=+1: also copy the '\0' to the new string */
	memcpy(xmitstat.helostr.s, helo, xmitstat.helostr.len--);

	if (!strcasecmp(helo, heloname.s)) {
		xmitstat.helostatus = 0;
		return 0;
	}

	s = getenv("TCPLOCALIP");
	if (s) {
		unsigned int sl = strlen(s);

		/* clear sign of spammers */
		if (!strcmp(helo, s)) {
			xmitstat.helostatus = 5;
			return 0;
		}
		/* I've never seen this happen, but it's also broken. It is valid if connection comes from
		 * localhost and process can't figure out hostname, but why not use qmail-inject or sendmail then? */
		if ((*helo == '[') && (helo[xmitstat.helostr.len - 1] == ']') && !strncmp(helo + 1, s, sl)) {
			xmitstat.helostatus = 2;
			return 0;
		}
	}
	/* check if the argument is a valid domain name */
	if (!domainvalid(helo)) {
		xmitstat.helostatus = 0;
		return 0;
	}

	xmitstat.helostatus = 3;
	/* it's not: it must be a IP literal enclosed in [] */
	if ((*helo != '[') || (!(s = strchr(xmitstat.helostr.s + 1, ']'))))
		return 0;

	/* there must not be any characters after the ']' */
	if (!*(s+1)) {
		struct in_addr ia;

		/* make the address string end where the ']' is so that inet_pton works */
		*s = '\0';
		if (inet_pton(AF_INET, xmitstat.helostr.s + 1, &ia))
			xmitstat.helostatus = 0;
		*s = ']';
	}
	return 0;
}

int
smtp_helo(void)
{
	const char *s[] = {"250 ", heloname.s, NULL};
	char *tmp;

	freedata();
	tmp = realloc(protocol, 5);
	if (tmp == NULL)
		return ENOMEM;
	protocol = tmp;
	memcpy(protocol, "SMTP", 5);
	xmitstat.esmtp = 0;
	xmitstat.spf = 0;
	xmitstat.datatype = 0;
	if (helovalid(linein + 5, linelen - 5) < 0)
		return errno;
	return net_writen(s) ? errno : 0;
}

int
smtp_ehlo(void)
{
	/* can this be self-growing? */
	const char *msg[] = {"250-", heloname.s, "\r\n250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n250-8BITMIME\r\n",
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
	unsigned int next = 3;	/* next index in to be used */
	char sizebuf[ULSTRLEN + 2]; /* holds a size and CRLF */
	int rc;
	char *authtypes = NULL;
	const char *localport = getenv("TCPLOCALPORT");

#ifdef CHUNKING
	msg[next++] = "250-CHUNKING\r\n";
#endif

	if (!ssl) {
		const char *protocol_esmtp = "ESMTP";
		char *tmp;
		tmp = realloc(protocol, strlen(protocol_esmtp) + 1);
		if (tmp == NULL)
			return ENOMEM;
		protocol = tmp;
		memcpy(protocol, protocol_esmtp, strlen(protocol_esmtp) + 1);	/* also copy trailing '\0' */
	}
	if (helovalid(linein + 5, linelen - 5) < 0)
		return errno;

	authtypes = smtp_authstring();

	if (authtypes != NULL) {
		msg[next++] = "250-AUTH";
		/* authtypes already includes trailing CRLF */
		msg[next++] = authtypes;
	}
/* check if STARTTLS should be announced. Don't announce if already in SSL mode or if certificate can't be opened */
	if (!ssl && ((localport == NULL) || (strcmp(localport, "465") != 0))) {
		const size_t oldlen = strlen(certfilename);
		int fd;

		certfilename[oldlen] = '.';
		strncpy(certfilename + oldlen + 1, xmitstat.localip,
				sizeof(certfilename) - oldlen - 1);
		fd = open(certfilename, O_RDONLY);
		if (fd < 0) {
			certfilename[oldlen] = '\0';
			fd = open(certfilename, O_RDONLY);
		}

		if (fd >= 0) {
			while (close(fd) && (errno == EINTR));
			msg[next++] = "250-STARTTLS\r\n";
		}
	}

/* this must stay last: it begins with "250 " */
	if (databytes) {
		msg[next++] = "250 SIZE ";
		ultostr(databytes, sizebuf);
		strcat(sizebuf, "\r\n");
		msg[next] = sizebuf;
	} else {
		msg[next] = "250 SIZE\r\n";
	}
	rc = (net_write_multiline(msg) < 0) ? errno : 0;
	xmitstat.spf = 0;
	xmitstat.esmtp = 1;
	xmitstat.datatype = 1;
	free(authtypes);
	return rc;
}

int
smtp_rcpt(void)
{
	struct recip *r;
	int i = 0, j, e;
	string tmp;
	char *more = NULL;
	struct userconf ds;
	const char *errmsg;
	int bt;			/* which policy matched */
	const char *logmsg[] = {"rejected message to <", NULL, "> from <", MAILFROM,
					"> from IP [", xmitstat.remoteip, "] {", NULL, ", ", NULL, " policy}", NULL};
	const char *okmsg[] = {"250 2.1.0 recipient <", NULL, "> OK", NULL};
	size_t bugoffset = 0;

	while ((bugoffset < linelen - 8) && (linein[8 + bugoffset] == ' '))
		bugoffset++;
	if (linein[8 + bugoffset] != '<')
		return EINVAL;
	if (bugoffset != 0)
		xmitstat.spacebug = 1;

	userconf_init(&ds);
	i = addrparse(linein + 9 + bugoffset, 1, &tmp, &more, &ds, rcpthosts, rcpthsize);
	if  (i > 0) {
		return i;
	} else if (i == -1) {
		logmsg[1] = tmp.s;
		logmsg[7] = "no such user}";
		logmsg[8] = NULL;
		log_writen(LOG_INFO, logmsg);
		free(tmp.s);
		return EBOGUS;
	} else if (i == -2) {
		j = is_authenticated();

		if (j < 0) {
			return -j;
		} else if (j == 0) {
			const char *logmess[] = {"rejected message to <", tmp.s, "> from <", MAILFROM,
					"> from IP [", xmitstat.remoteip, "] {relaying denied}", NULL};

			log_writen(LOG_INFO, logmess);
			free(tmp.s);
			userconf_free(&ds);
			tarpit();
			return netwrite("551 5.7.1 relaying denied\r\n") ? errno : EBOGUS;
		}
	}
	/* we do not support any ESMTP extensions adding data behind the RCPT TO (now)
	 * so any data behind the '>' is a bug in the client */
	if (more) {
		userconf_free(&ds);
		free(tmp.s);
		return EINVAL;
	}
	if (rcptcount >= MAXRCPT) {
		userconf_free(&ds);
		free(tmp.s);
		return netwrite("452 4.5.3 Too many recipients\r\n") ? errno : 0;
	}
	r = malloc(sizeof(*r));
	if (!r) {
		userconf_free(&ds);
		free(tmp.s);
		return ENOMEM;
	}
	r->to.s = tmp.s;
	r->to.len = tmp.len;
	r->ok = 0;	/* user will be rejected until we change this explicitely */
	thisrecip = r;
	TAILQ_INSERT_TAIL(&head, r, entries);
	rcptcount++;

/* load user and domain "filterconf" file */
	e = userconf_load_configs(&ds);
	if (e != 0) {
		userconf_free(&ds);
		return err_control2("user/domain filterconf for ", r->to.s) ? errno : EDONE;
	}

	i = j = e = 0;
	while (rcpt_cbs[j]) {
		errmsg = NULL;
		if ( (i = rcpt_cbs[j](&ds, &errmsg, &bt)) ) {
			int t;

			if (i == 5)
				break;

			if (i == 4) {
				e = 1;
				if (getsetting(&ds, "fail_hard_on_temp", &t))
					i = 1;
			}
			if (i == 1) {
				if (getsetting(&ds, "nonexist_on_block", &t))
					i = 3;
			}

			if (i == -1) {
				char filterno[ULSTRLEN];
				char errnostr[ULSTRLEN];
				const char *logmess[] = {"error ", errnostr, " in filter ", filterno, " for user ", r->to.s, NULL};

				ultostr(errno, errnostr);
				ultostr(j, filterno);

				log_writen(LOG_WARNING, logmess);
				e = 1;
			} else if (i != 4) {
				break;
			}
		}
		j++;
	}
	userconf_free(&ds);

	if ((i == 0) && e)
		i = 4;
	if (i && (i != 5))
		goto userdenied;

	if (comstate != 0x20) {
		if (!xmitstat.mailfrom.len) {
			const char *logmess[] = {"rejected message to <> from <", NULL, "> from IP [", xmitstat.remoteip,
							"] {bad bounce}", NULL};
			if (err_badbounce() < 0)
				return errno;
			if (!badbounce) {
				/* there are only two recipients in list until now */
				struct recip *l = head.tqh_first;

				logmess[1] = l->to.s;
				log_writen(LOG_INFO, logmess);
				TAILQ_REMOVE(&head, head.tqh_first, entries);
				badbounce = 1;
				l->ok = 0;
			}
			logmess[1] = r->to.s;
			log_writen(LOG_INFO, logmess);
			goodrcpt = 0;
			rcptcount = 0;
			return EBOGUS;
		}
	}
	goodrcpt++;
	r->ok = 1;
	okmsg[1] = r->to.s;

	return net_writen(okmsg) ? errno : 0;
userdenied:
	e = errno;
	if (errmsg && (i > 0)) {
		logmsg[7] = errmsg;
		logmsg[9] = blocktype[bt];
		logmsg[1] = r->to.s;
		log_writen(LOG_INFO, logmsg);
	}
	if (i > 0)
		tarpit();
	switch (i) {
	case -1:
		j = 1;
		break;
	case 2:
		if ( (j = netwrite("550 5.7.1 mail denied for policy reasons\r\n")) )
			e = errno;
		break;
	case 3:	{
			const char *rcptmsg[] = {"550 5.1.1 no such user <", r->to.s, ">", NULL};

			if ( (j = net_writen(rcptmsg)) )
				e = errno;
		}
		break;
	case 4:
		if ( (j = netwrite("450 4.7.0 mail temporary denied for policy reasons\r\n")) )
			e = errno;
		break;
	}
	return j ? e : 0;
}

int
smtp_from(void)
{
	int i = 0;
	char *more = NULL;
	/* this is the maximum allowed length of the command line. Since every extension
	 * may raise this we use this variable. Every successfully used command extension
	 * will raise this counter by the value defined in the corresponding RfC.
	 * The limit is defined to 512 characters including CRLF (which we do not count)
	 * in RfC 2821, section 4.5.3.1 */
	unsigned int validlength = 510;
	int seenbody = 0;	/* if we found a "BODY=" after mail, there may only be one */
	struct userconf ds;
	struct statvfs sbuf;
	const char *okmsg[] = {"250 2.1.5 sender <", NULL, "> is syntactically correct", NULL};
	char *s;
	size_t bugoffset = 0;

	/* detect broken clients that have spaces between ':' and '<' */
	while ((bugoffset < linelen - 10) && (linein[10 + bugoffset] == ' '))
		bugoffset++;
	if (linein[10 + bugoffset] != '<')
		return EINVAL;
	if (bugoffset != 0)
		xmitstat.spacebug = 1;

	/* if we are in submission mode we require authentication before any mail */
	if (submission_mode) {
		int r = is_authenticated();
		if (r < 0) {
			return -r;
		} else if (!r) {
			if (netwrite("550 5.7.1 authentication required\r\n") < 0)
				return errno;
			return EDONE;
		}
	}

	userconf_init(&ds);
	i = addrparse(linein + 11 + bugoffset, 0, &(xmitstat.mailfrom), &more, &ds, rcpthosts, rcpthsize);
	xmitstat.frommx = NULL;
	xmitstat.fromdomain = 0;
	userconf_free(&ds);
	if (i > 0)
		return i;
	else if (i == -1) {
		free(xmitstat.mailfrom.s);
		return EBOGUS;
	}
	xmitstat.thisbytes = 0;
	/* data behind the <..> is only allowed in ESMTP */
	if (more && !xmitstat.esmtp)
		return EINVAL;
	while (more && *more) {
		if (!strncasecmp(more, " SIZE=", 6)) {
			char *sizenum = more + 6;

			/* this is only set if we found SIZE before; there should only be one */
			if (xmitstat.thisbytes)
				return EINVAL;
			if ((*sizenum >= '0') && (*sizenum <= '9')) {
				char *end;
				xmitstat.thisbytes = strtoul(sizenum, &end, 10);
				/* the line length limit is raised by 26 characters
				 * in RfC 1870, section 3. */
				validlength += 26;
				more = end;
			} else
				return EINVAL;
		} else if (!strncasecmp(more, " BODY=", 6)) {
			char *bodytype = more + 6;

			if (seenbody)
				return EINVAL;
			seenbody = 1;
			if (!strncasecmp(bodytype, "7BIT", 4)) {
				more = bodytype + 4;
				xmitstat.datatype = 0;
			} else if (!strncasecmp(bodytype, "8BITMIME", 8)) {
				more = bodytype + 8;
				xmitstat.datatype = 1;
			} else
				return EINVAL;
		} else if (!strncasecmp(more, " AUTH=", 6)) {
			char *authstr = more + 6;
			ssize_t xlen = xtextlen(authstr);

			if (xlen <= 0)
				return EINVAL;

			validlength += 500;
			more += xlen + 6;
		} else
			return EBADRQC;

		if (*more && (*more != ' '))
			return EINVAL;
		continue;
	}
	if (linelen > validlength)
		return E2BIG;

	while ( ( i = statvfs("queue/lock/sendmutex", &sbuf)) ) {
		int e;

		switch (e = errno) {
		case EINTR:
			break;
		case ENOMEM:
			return e;
		case ENOENT:	/* uncritical: only means that qmail-send is not running */
		case ENOSYS:
		/* will happen in most cases because program runs not in group qmail */
		case EACCES:
			log_write(LOG_WARNING, "warning: can not get free queue disk space");
			goto next;
/*		case ELOOP:
		case ENAMETOOLONG:
		case ENOTDIR:
		case EOVERFLOW:
		case EIO:*/
		/* the other errors not named above should really never happen so
			* just use default to get better code */
		default:
			log_write(LOG_ERR, "critical: can not get free queue disk space");
			return e;
		}
	}
next:
	if (!i) {
		if (sbuf.f_flag & ST_RDONLY)
			return EROFS;
		/* check if the free disk in queue filesystem is at least the size of the message */
		if ((databytes && (databytes < xmitstat.thisbytes)) || (sbuf.f_bsize*sbuf.f_bavail < xmitstat.thisbytes))
			return netwrite("452 4.3.1 Requested action not taken: insufficient system storage\r\n") ? errno : EDONE;
	}

	/* no need to check existence of sender domain on bounce message */
	if (xmitstat.mailfrom.len) {
		/* strchr can't return NULL here, we have checked xmitstat.mailfrom.s before */
		xmitstat.fromdomain = ask_dnsmx(strchr(xmitstat.mailfrom.s, '@') + 1, &xmitstat.frommx);
		if (xmitstat.fromdomain < 0)
			return errno;
		s = strchr(xmitstat.mailfrom.s, '@') + 1;
	} else {
		xmitstat.fromdomain = 0;
		xmitstat.frommx = NULL;
		s = HELOSTR;
	}

	i = open(connection_is_ipv4() ? "control/spffriends" : "control/spffriends6", O_RDONLY);

	if ((i < 0) && (errno != ENOENT)) {
		return err_control(connection_is_ipv4() ? "control/spffriends" : "control/spffriends6") ?
				errno : EDONE;
	} else if (i >= 0) {
		i = lookupipbl(i);
		if (i < 0)
			return netwrite("421 4.3.5 unable to read controls\r\n") ? errno : EDONE;
	}

	/* i is <0 if no spffriends file found and ==0 if not whitelisted */
	if (i > 0) {
		xmitstat.spf = SPF_IGNORE;
	} else {
		i = check_host(s);
		if (i < 0)
			return errno;
		xmitstat.spf = (i & 0x0f);
	}

	badbounce = 0;
	goodrcpt = 0;
	okmsg[1] = MAILFROM;
	return net_writen(okmsg) ? errno : 0;
}

int
smtp_vrfy(void)
{
	return netwrite("252 send some mail, I'll do my very best\r\n") ? errno : 0;
}

int
smtp_noop(void)
{
	sync_pipelining();
	return netwrite("250 2.0.0 ok\r\n") ? errno : 0;
}

int
smtp_rset(void)
{
	if (comstate == 0x0800)
		rset_queue();
	/* if there was EHLO or HELO before we reset to the state to immediately after this */
	if (comstate >= 0x008) {
		freedata();
		commands[2].state = (0x008 << xmitstat.esmtp);
	}
	/* we don't need the else case here: if there was no helo/ehlo no one has changed .state */
	return netwrite("250 2.0.0 ok\r\n") ? errno : 0;
}

/**
 * \brief clean up the allocated data and exit the process
 * \param rc desired return code of the process
 */
void
conn_cleanup(const int rc)
{
	freedata();
	freeppol();
	userbackend_free();

	free(protocol);
	free(gcbuf);
	free(globalconf);
	free(heloname.s);
	free(msgidhost.s);
	exit(rc);
}

int
smtp_quit(void)
{
	const char *msg[] = {"221 2.0.0 ", heloname.s, " service closing transmission channel", NULL};
	int rc;

	rc = net_writen(msg);
	conn_cleanup(rc ? errno : 0);
}

static int
smtp_temperror(void)
{
	return netwrite("451 4.3.5 system config error\r\n") ? errno : EDONE;
}

/**
 * http_post - handle HTTP POST request
 *
 * This has nothing to do with SMTP at all. But I have seen many proxy attempts
 * trying to send spam and beginning the connection with a sequence like this:
 *
 * > POST / HTTP/1.0
 * > Via: 1.0 SERVEUR
 * > Host: mail.sf-mail.de:25
 * > Content-Length: 1255
 * > Content-Type: text/plain
 * > Connection: Keep-Alive
 * >
 * > RSET
 *
 * This function is only there to handle this connections and drop them as early as possible to save our traffic.
 */
int
http_post(void)
{
	if (comstate != 0x001)
		return EINVAL;
	if (!strncmp(" / HTTP/1.", linein + 4, 10)) {
		const char *logmsg[] = {"dropped connection from [", xmitstat.remoteip, "]: client is talking HTTP to me", NULL};
		log_writen(LOG_INFO, logmsg);
		exit(0);
	}
	return EINVAL;
}

/**
 * line_valid - check if input line contains only syntactically correct characters
 * @returns: 0 on success, else error code
 */
static int
line_valid()
{
	size_t i;

	for (i = 0; i < linelen; i++) {
		/* linein is signed char, so non-ASCII characters are <0 */
		if (linein[i] <= 0)
			return EINVAL;
	}
	return 0;
}

static int flagbogus;

static void __attribute__ ((noreturn))
smtploop(void)
{
	badcmds = 0;

	assert(strcmp(commands[1].name, "QUIT") == 0);
	if (!getenv("BANNER")) {
		const char *msg[] = {"220 ", heloname.s, " " VERSIONSTRING " ESMTP", NULL};

		flagbogus = hasinput(0);
		switch (flagbogus) {
		case EBOGUS:
			/* check if someone talks to us like a HTTP proxy and kill the connection if */
			if (!strncmp("POST / HTTP/1.", linein, 14)) {
				const char *logmsg[] = {"dropped connection from [", xmitstat.remoteip,
						"]: client is talking HTTP to me", NULL };
				log_writen(LOG_INFO, logmsg);
				exit(0);
			} else {
				/* this is just a broken SMTP engine */
				wait_for_quit();
			}
		case 0:
			flagbogus = net_writen(msg) ? errno : 0;
			if (flagbogus == 0)
				break;
		default:
			/* There was a communication error. Announce temporary error. */
			(void) net_writen(msg);

			(void) net_read();

			/* explicitely catch QUIT here: responding with 450 here is bogus */
			if (!strncasecmp(linein, commands[1].name, commands[1].len)) {
				if (!linein[commands[1].len])
					smtp_quit();
			}
			netwrite("450 4.5.0 transmission error, please try again\r\n");

			/* a conformant client would catch this error, send quit and try again.
			 * So just wait for quit and reject any further command. */
			wait_for_quit();
		}
	}

/* the state machine */
	while (1) {
		unsigned int i;
/* read the line (but only if there is not already an error condition, in this case handle the error first) */
		if (!flagbogus) {
			flagbogus = net_read();

/* sanity checks */
			/* we are not in DATA here so there MUST NOT be a non-ASCII character,
			* '\0' is also bogus */
			if (!flagbogus) {
				flagbogus = line_valid();
			} else
				flagbogus = errno;
		}

/* error handling */
		if (flagbogus) {
			check_max_bad_commands();
			/* set flagbogus again in the switch statement to check if an error
			 * occured during error handling. This is a very bad sign: either
			 * we are very short of resources or the client is really really broken */
			switch (flagbogus) {
			case EBADRQC:	tarpit();
					log_write(LOG_INFO, "bad SMTP command parameter");
					flagbogus = netwrite("501 5.5.2 unrecognized command parameter\r\n") ? errno : 0;
					break;
			case EINVAL:	tarpit();
					log_write(LOG_INFO, "bad SMTP command syntax");
					flagbogus = netwrite("500 5.5.2 command syntax error\r\n") ? errno : 0;
					break;
			case E2BIG:	tarpit();
					log_write(LOG_INFO, "too long SMTP line");
					flagbogus = netwrite("500-5.5.2 line too long\r\n500-5.5.2 This is usually a bug in your mail client\r\n500 5.5.2 Try to use a different encoding like quoted-printable for this mail.\r\n") ? errno : 0;
					break;
			case ENOMEM:	/* ignore errors for the first 2 messages: if the third
						* one succeeds everything is ok */
					netwrite("452-4.3.0 out of memory\r\n");
					sleep(30);
					netwrite("452-4.3.0 give me some time to recover\r\n");
					sleep(30);
					badcmds = 0;
					log_write(LOG_ERR, "out of memory");
					flagbogus = netwrite("452 4.3.0 please try again later\r\n") ? errno : 0;
					break;
			case EIO:	badcmds = 0;
					log_write(LOG_ERR, "IO error");
					flagbogus = netwrite("451 4.3.0 IO error, please try again later\r\n") ? errno : 0;
					break;
			case EMSGSIZE:	badcmds = 0;
					flagbogus = netwrite("552 4.3.1 Too much mail data\r\n") ? errno : 0;
					break;
			case EPROTO:	flagbogus = netwrite("550 5.7.5 data encryption error\r\n") ? errno : 0;
					break;
			case EROFS:	log_write(LOG_ERR, "HELP! queue filesystem looks read only!");
					badcmds = 0;
					flagbogus = netwrite("452 4.3.5 cannot write to queue\r\n") ? errno : 0;
					break;
			case 1:		tarpit();
					flagbogus = netwrite("503 5.5.1 Bad sequence of commands\r\n") ? errno : 0;
					break;
			case EDONE:	badcmds = 0;	/* fallthrough */
			case EBOGUS:	flagbogus = 0;
					break;
			case EINTR:	log_write(LOG_WARNING, "interrupted by signal");
					_exit(EINTR);
			case ECONNRESET:dieerror(flagbogus);
			default:	log_write(LOG_ERR, "writer error. kick me.");
					log_write(LOG_ERR, strerror(flagbogus));
					badcmds = 0;
					flagbogus = netwrite("500 5.3.0 unknown error\r\n") ? errno : 0;
			}
			/* do not work on the command now: it was either not read or was bogus.
			 * Start again and try to read one new to see if it get's better */
			continue;
		}

/* set flagbogus to catch if client writes crap. Will be overwritten if a good command comes in */
		flagbogus = EINVAL;
/* handle the commands */
		for (i = 0; i < sizeof(commands) / sizeof(struct smtpcomm); i++) {
			if (!strncasecmp(linein, commands[i].name, commands[i].len)) {
				if (comstate & commands[i].mask) {
					if (!(commands[i].flags & 2) && (linelen > 510)) {
						/* RfC 2821, section 4.5.3.1 defines the maximum length of a command line
						 * to 512 chars if this limit is not raised by an extension. Since we
						 * stripped CRLF our limit is 510. A command may override this check and
						 * check line length by itself */
						 flagbogus = E2BIG;
						 break;
					}
					if (!(commands[i].flags & 1) && linein[commands[i].len]) {
						flagbogus = EINVAL;
					} else
						flagbogus = commands[i].func();

					/* command succeded */
					if (!flagbogus) {
						if (commands[i].state > 0)
							comstate = commands[i].state;
						else if (!commands[i].state)
							comstate = (1 << i);
						flagbogus = 0;
						badcmds = 0;
					}
				} else
					flagbogus = 1;
				break;
			}
		}
	}
}

int
main(int argc, char **argv)
{
	const char *localport = getenv("TCPLOCALPORT");

	if (setup()) {
		/* setup failed: make sure we wait until the "quit" of the other host but
		 * do not process any mail. Commands RSET, QUIT and NOOP are still allowed.
		 * The state will not change so a client ignoring our error code will get
		 * "bad sequence of commands" and will be kicked if it still doesn't care */
		int i;
		for (i = (sizeof(commands) / sizeof(struct smtpcomm)) - 1; i > 2; i--) {
			commands[i].func = smtp_temperror;
			commands[i].state = -1;
		}
	} else {
		STREMPTY(xmitstat.authname);
		xmitstat.check2822 = 2;
		TAILQ_INIT(&head);		/* Initialize the recipient list. */
	}

	submission_mode = (localport != NULL) && (strcmp(localport, "587") == 0);

	/* Assume all given parameters are for auth checking */
	auth_setup(argc, (const char **) argv);

	if (connsetup() < 0)
		flagbogus = errno;
	smtploop();
}
