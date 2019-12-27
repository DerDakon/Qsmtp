/** \file qsmtpd.c
 \brief main part of Qsmtpd

 This file contains the main function and the basic commands of Qsmtpd
 SMTP server.
 */

#include <qsmtpd/qsmtpd.h>

#include <control.h>
#include <diropen.h>
#include <log.h>
#include <mmap.h>
#include <netio.h>
#include <qdns.h>
#include <qmaildir.h>
#include <qsmtpd/antispam.h>
#include <qsmtpd/commands.h>
#include <qsmtpd/qsauth.h>
#include <qsmtpd/qsdata.h>
#include <qsmtpd/starttls.h>
#include <qsmtpd/syntax.h>
#include <qsmtpd/userconf.h>
#include <sstring.h>
#include <tls.h>
#include <version.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define _C(c, m, f, s, o) { .name = c, .len = sizeof(c) - 1, .mask = m, .func = f, .state = s, .flags = o }

struct smtpcomm *current_command;

static struct smtpcomm commands[] = {
	_C("NOOP",	0xffff, smtp_noop,      -1, 0), /* 0x0001 */
	_C("QUIT",	0xfffd, smtp_quit,       0, 0), /* 0x0002 */
	_C("RSET",	0xfffd, smtp_rset,     0x1, 0), /* 0x0004 */ /* the status to change to is set in smtp_rset */
	_C("HELO",	0xfffd, smtp_helo,       0, 5), /* 0x0008 */
	_C("EHLO",	0xfffd, smtp_ehlo,       0, 5), /* 0x0010 */
	_C("MAIL FROM:",0x0018, smtp_from,       0, 3), /* 0x0020 */
	_C("RCPT TO:",	0x0060, smtp_rcpt,       0, 1), /* 0x0040 */
	_C("DATA",	0x0040, smtp_data,    0x10, 0), /* 0x0080 */ /* the status to change to is changed in smtp_data */
	_C("STARTTLS",	0x0010, smtp_starttls, 0x1, 0), /* 0x0100 */
	_C("AUTH",	0x0010, smtp_auth,      -1, 5), /* 0x0200 */
	_C("VRFY",	0xffff, smtp_vrfy,      -1, 5), /* 0x0400 */
#ifdef CHUNKING
	_C("BDAT",	0x0840, smtp_bdat,      -1, 5), /* 0x0800 */ /* the status to change to is changed in smtp_bdat */
#endif
	_C("POST",	0xffff, http_post,      -1, 1)  /* 0x1000 */ /* this should stay last */
};

#undef _C

unsigned int rcptcount;			/**< number of recipients in lists including rejected */
int relayclient;			/**< flag if this client is allowed to relay by IP: 0 unchecked, 1 allowed, 2 denied */
char *rcpthosts;			/**< memory mapping of control/rcpthosts */
off_t rcpthsize;			/**< sizeof("control/rcpthosts") */
unsigned long sslauth;			/**< if SMTP AUTH is only allowed after STARTTLS */
unsigned long databytes;		/**< maximum message size */
unsigned int goodrcpt;			/**< number of valid recipients */
struct xmitstat xmitstat;		/**< This contains some flags describing the transmission and it's status. */
const char **globalconf;		/**< contents of the global "filterconf" file (or NULL) */
string heloname;			/**< the fqdn to show in helo */
string msgidhost;			/**< the fqdn to use if a message-id is added */
string liphost;				/**< replacement domain if TO address is <foo@[ip]> */
int socketd = 1;			/**< the descriptor where messages to network are written to */
unsigned long comstate = 0x001;		/**< status of the command state machine, initialized to noop */
int authhide;				/**< hide source of authenticated mail */
int submission_mode;			/**< if we should act as message submission agent */

struct recip *thisrecip;

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
int
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
	const char *logmsg[] = { "connection from [", xmitstat.remoteip, NULL, NULL, NULL };

	switch (error) {
	case ETIMEDOUT:
		logmsg[2] = "] timed out";
		break;
	case ECONNRESET:
		logmsg[2] = "] died";
		break;
	default:
		logmsg[2] = "] failed, error: ";
		logmsg[3] = strerror(error);
		break;
	}
	log_writen(LOG_WARNING, logmsg);
	conn_cleanup(error);
}

static int
setup(void)
{
	char *tmp;
	unsigned long tl;
	char **tmpconf;
	int rcpthfd;		/* file descriptor of control/rcpthosts */

#ifdef USESYSLOG
	openlog("Qsmtpd", LOG_PID, LOG_MAIL);
#endif

	/* make sure to have a reasonable default timeout if errors happen */
	timeout = 320;

	if (chdir(AUTOQMAIL)) {
		log_write(LOG_ERR, "cannot chdir to qmail directory");
		return EINVAL;
	}

	controldir_fd = get_dirfd(-1, AUTOQMAIL "/control");
	if (controldir_fd < 0) {
		log_write(LOG_ERR, "cannot get a file descriptor for " AUTOQMAIL "/control");
		return EINVAL;
	}

#ifdef DEBUG_IO
	tmp = getenv("QSMTPD_DEBUG");
	if ((tmp != NULL) && (*tmp != '\0'))
		do_debug_io = 1;
	else
		do_debug_io = (faccessat(controldir_fd, "Qsmtpd_debug", R_OK, 0) == 0);
#endif

	int j = loadoneliner(controldir_fd, "me", &heloname.s, 0);
	if (j < 0)
		return errno;
	heloname.len = j;
	if (domainvalid(heloname.s)) {
		log_write(LOG_ERR, "control/me contains invalid name");
		return EINVAL;
	}

	j = loadoneliner(controldir_fd, "msgidhost", &msgidhost.s, 1);
	if (j < 0) {
		j = dupstr(&msgidhost, heloname.s);
		if (j != 0)
			return errno;
	} else {
		msgidhost.len = j;
		if (domainvalid(msgidhost.s)) {
			log_write(LOG_ERR, "control/msgidhost contains invalid name");
			return EINVAL;
		}
	}

	if (( (j = loadoneliner(controldir_fd, "localiphost", &liphost.s, 1)) < 0) && (errno != ENOENT))
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

	rcpthosts = mmap_name(controldir_fd, "rcpthosts", &rcpthsize, &rcpthfd);

	if (rcpthosts == NULL) {
		int e = errno;

		switch (e) {
		case ENOENT:
			rcpthsize = 0;
			/* fallthrough */
		case 0:
			assert(rcpthsize == 0);
			/* allow this, this just means that no host is local */
			break;
		default:
			log_write(LOG_ERR, "cannot map control/rcpthosts");
			errno = e;
			return -1;
		}
	}

	if ((rcpthsize > 0) && (rcpthsize < 4)) {
		/* minimum length of domain name: x.yy = 4 bytes */
		log_write(LOG_ERR, "control/rcpthosts too short");
		munmap(rcpthosts, rcpthsize);
		rcpthosts = NULL;
		return 1;
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
	if ( (j = loadintfd(openat(controldir_fd, "timeoutsmtpd", O_RDONLY | O_CLOEXEC), &tl, 320)) ) {
		int e = errno;
		log_write(LOG_ERR, "parse error in control/timeoutsmtpd");
		return e;
	}
	timeout = tl;
	if ( (j = loadintfd(openat(controldir_fd, "databytes", O_RDONLY | O_CLOEXEC), &databytes, 0)) ) {
		int e = errno;
		log_write(LOG_ERR, "parse error in control/databytes");
		return e;
	}
	if (databytes) {
		maxbytes = databytes;
	} else {
		maxbytes = ((size_t)-1) - 1000;
	}
	if ( (j = loadintfd(openat(controldir_fd, "authhide", O_RDONLY | O_CLOEXEC), &tl, 0)) ) {
		log_write(LOG_ERR, "parse error in control/authhide");
		authhide = 0;
	} else {
		authhide = tl ? 1 : 0;
	}

	if ( (j = loadintfd(openat(controldir_fd, "forcesslauth", O_RDONLY | O_CLOEXEC), &sslauth, 0)) ) {
		int e = errno;
		log_write(LOG_ERR, "parse error in control/forcesslauth");
		return e;
	}

	if ( (j = loadlistfd(openat(controldir_fd, "filterconf", O_RDONLY | O_CLOEXEC), &tmpconf, NULL)) ) {
		if ((errno == ENOENT) || (tmpconf == NULL)) {
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

	/* Block SIGPIPE, otherwise write errors can't be handled correctly and remote host
	 * will see a connection drop on error (which is bad and violates RfC) */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGPIPE);
	j = sigprocmask(SIG_BLOCK, &mask, NULL);

	relayclient = 0;

	return j;
}

/** initialize variables related to this connection */
static int
connsetup(void)
{
#ifdef IPV4ONLY
	xmitstat.ipv4conn = 1;
#else /* IPV4ONLY */
	xmitstat.ipv4conn = IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip) ? 1 : 0;
#endif /* IPV4ONLY */

	int j = ask_dnsname(&xmitstat.sremoteip, &xmitstat.remotehost.s);
	if (j == DNS_ERROR_LOCAL) {
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
	while (!TAILQ_EMPTY(&head)) {
		struct recip *l = TAILQ_FIRST(&head);

		TAILQ_REMOVE(&head, TAILQ_FIRST(&head), entries);
		free(l->to.s);
		free(l);
	}
	rcptcount = 0;
	goodrcpt = 0;
}

/**
 * @brief fork() but clean up internal structures
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

	userbackend_free();
	munmap(rcpthosts, rcpthsize);

#ifdef USESYSLOG
	closelog();
#endif /* USESYSLOG */

	if (ssl) {
		int rfd = SSL_get_rfd(ssl);
		int wfd = SSL_get_wfd(ssl);

		/* the fds need to be removed from SSL first, otherwise
		 * destroying the SSL object will terminate the SSL connection
		 * to the remote host. */
		SSL_set_fd(ssl, -1);
		close(wfd);
		if (rfd != wfd)
			close(rfd);

		ssl_free(ssl);
	}

	return 0;
}

/**
 * \brief clean up the allocated data and exit the process
 * \param rc desired return code of the process
 */
void
conn_cleanup(const int rc)
{
	freedata();
	userbackend_free();
	free(xmitstat.authname.s);

	free(globalconf);
	free(heloname.s);
	free(msgidhost.s);
	exit(rc);
}

static int
smtp_temperror(void)
{
	return netwrite("451 4.3.5 system config error\r\n") ? errno : EDONE;
}

/**
 * line_valid - check if input line contains only syntactically correct characters
 * @returns: 0 on success, else error code
 */
static int
line_valid()
{
	for (size_t i = 0; i < linein.len; i++) {
		/* linein is signed char, so non-ASCII characters are <0 */
		if (linein.s[i] <= 0)
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
			if (!strncmp("POST / HTTP/1.", linein.s, 14)) {
				const char *logmsg[] = {"dropped connection from [", xmitstat.remoteip,
						"]: client is talking HTTP to me", NULL };
				log_writen(LOG_INFO, logmsg);
				exit(0);
			} else {
				/* this is just a broken SMTP engine */
				wait_for_quit();
			}
		case 0:
			flagbogus = -net_writen(msg);
			if (flagbogus == 0)
				break;
			/* fallthrough */
		default:
			/* There was a communication error. Announce temporary error. */
			(void) net_writen(msg);

			(void) net_read(1);

			/* explicitely catch QUIT here: responding with 450 here is bogus */
			if (!strncasecmp(linein.s, commands[1].name, commands[1].len)) {
				if (!linein.s[commands[1].len])
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
/* read the line (but only if there is not already an error condition, in this case handle the error first) */
		if (!flagbogus) {
			flagbogus = net_read(1);

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
			case ENOEXEC:	tarpit();
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
		for (unsigned int i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
			if (!strncasecmp(linein.s, commands[i].name, commands[i].len)) {
				if (comstate & commands[i].mask) {
					const long ostate = commands[i].state; /* the state originally recorded for this command */

					/* "space required" may not come without "takes arguments" */
					assert((commands[i].flags & 5) != 4);
					if (!(commands[i].flags & 2) && (linein.len > 510)) {
						/* RfC 2821, section 4.5.3.1 defines the maximum length of a command line
						 * to 512 chars if this limit is not raised by an extension. Since we
						 * stripped CRLF our limit is 510. A command may override this check and
						 * check line length by itself */
						 flagbogus = E2BIG;
						 break;
					}

					if (!(commands[i].flags & 1) && linein.s[commands[i].len]) {
						flagbogus = EINVAL;
					} else if ((commands[i].flags & 4) && (linein.s[commands[i].len] != ' ')) {
						flagbogus = EINVAL;
					} else {
						current_command = commands + i;
						flagbogus = commands[i].func();
						current_command = NULL;
					}

					/* command succeded */
					if (!flagbogus) {
						if (commands[i].state > 0)
							comstate = commands[i].state;
						else if (!commands[i].state)
							comstate = (1 << i);
						badcmds = 0;
					}
					commands[i].state = ostate;	/* in case a command has changed that */
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
