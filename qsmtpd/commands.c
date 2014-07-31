#include <qsmtpd/commands.h>

#include <fmt.h>
#include <log.h>
#include <netio.h>
#include <qsmtpd/addrparse.h>
#include <qsmtpd/antispam.h>
#include <qsmtpd/qsauth.h>
#include <qsmtpd/queue.h>
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/starttls.h>
#include <qsmtpd/syntax.h>
#include <qsmtpd/userfilters.h>
#include <qsmtpd/xtext.h>
#include <qsmtpd/userconf.h>
#include <tls.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/queue.h>
#include <sys/statvfs.h>
#include <unistd.h>

char certfilename[24 + INET6_ADDRSTRLEN + 6];		/**< path to SSL certificate filename */

#define MAXRCPT		500		/**< maximum number of recipients in a single mail */

/**
 * check if the argument given to HELO/EHLO is syntactically correct
 *
 * @param helo helo to check
 * @param len length of helo
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
static int __attribute__ ((nonnull (1)))
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

/**
 * @brief check if the remote host is listed in local IP map file given by filename
 * @param filename name of ipbl file
 * @retval <0 negative error code
 * @retval >0 on match
 * @retval 0 no match
 * @retval -EDONE an error message was already written to the network
 */
static int
lookupipbl_name(const char *filename)
{
	int fd = openat(controldir_fd, filename, O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		if (errno != ENOENT)
			return err_control2("control/", filename) ? -errno : -EDONE;
		return 0;
	}

	fd = lookupipbl(fd);
	if (fd < 0)
		return err_control2("error reading from ipbl file: ", filename) ? -errno : -EDONE;
	else
		return fd;
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
		const int ipbl = lookupipbl_name(connection_is_ipv4() ?
				"relayclients" : "relayclients6");

		/* reject everything on parse error, else this
		 * would turn into an open relay by accident */
		relayclient = 2;
		if (ipbl < 0)
			return ipbl;
		else if (ipbl > 0)
			relayclient = 1;
	}

	if (!(relayclient & 1)) {
		int i = tls_verify();
		if (i < 0)
			return i;

		relayclient = i ? 1 : relayclient;
	}

	return (relayclient == 1) ? 1 : 0;
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
	if (helovalid(linein.s + 5, linein.len - 5) < 0)
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
	if (helovalid(linein.s + 5, linein.len - 5) < 0)
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
		const size_t diroffs = strlen("control/");
		size_t iplen;
		int fd;

		/* append ".<ip>" to the normal certfilename */
		certfilename[oldlen] = '.';
		strncpy(certfilename + oldlen + 1, xmitstat.localip,
				sizeof(certfilename) - oldlen - 1);

		if (localport != NULL) {
			/* if we know the local port, append ":<port>" */
			iplen = oldlen + 1 + strlen(xmitstat.localip);
			certfilename[iplen] = ':';
			strncpy(certfilename + iplen + 1, localport,
					sizeof(certfilename) - iplen - 1);
		}

		fd = faccessat(controldir_fd, certfilename + diroffs, R_OK, 0);
		if ((fd < 0) && (localport != NULL)) {
			/* if we know the port, but no file with the port exists
			 * try without the port now */
			certfilename[iplen] = '\0';
			fd = faccessat(controldir_fd, certfilename + diroffs, R_OK, 0);
		}

		if (fd < 0) {
			/* the certificate has not been found with ip, try the
			 * general name. */
			certfilename[oldlen] = '\0';
			fd = faccessat(controldir_fd, certfilename + diroffs, R_OK, 0);
		}

		if (fd == 0)
			msg[next++] = "250-STARTTLS\r\n";
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
	enum filter_result fr;	/* result of user filter */
	string tmp;
	char *more = NULL;
	struct userconf ds;
	const char *errmsg;
	enum config_domain bt;			/* which policy matched */
	const char *logmsg[] = { "temporarily ", "rejected message to <", NULL, "> from <", MAILFROM,
					"> from IP [", xmitstat.remoteip, "] {", NULL, ", ", NULL, " policy}", NULL };
	const char *okmsg[] = { "250 2.1.0 recipient <", NULL, "> OK", NULL };
	size_t bugoffset = 0;

	while ((bugoffset < linein.len - 8) && (linein.s[8 + bugoffset] == ' '))
		bugoffset++;
	if (linein.s[8 + bugoffset] != '<')
		return EINVAL;
	if (bugoffset != 0)
		xmitstat.spacebug = 1;

	userconf_init(&ds);
	i = addrparse(linein.s + 9 + bugoffset, 1, &tmp, &more, &ds, rcpthosts, rcpthsize);
	if  (i > 0) {
		return i;
	} else if (i == -1) {
		logmsg[2] = tmp.s;
		logmsg[8] = "no such user}";
		logmsg[9] = NULL;
		log_writen(LOG_INFO, logmsg + 1);
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

	if ((rcptcount > 0) && (xmitstat.mailfrom.len == 0)) {
		const char *logmess[] = {"rejected message to <", NULL, "> from <> from IP [", xmitstat.remoteip,
						"] {bad bounce}", NULL};
		struct recip *l = TAILQ_FIRST(&head);

		tarpit();
		if (netwrite("550 5.5.3 bounce messages must not have more than one recipient\r\n") != 0)
			return errno;

		if (l->ok) {
			/* this can only happen on the first call */
			logmess[1] = l->to.s;
			log_writen(LOG_INFO, logmess);
			l->ok = 0;
		}
		badbounce = 1;
		logmess[1] = r->to.s;
		log_writen(LOG_INFO, logmess);
		goodrcpt = 0;
		rcptcount = 0;
		return EBOGUS;
	}

	rcptcount++;

/* load user and domain "filterconf" file */
	i = userconf_load_configs(&ds);
	if (i != 0) {
		userconf_free(&ds);
		return err_control2("user/domain filterconf for ", r->to.s) ? errno : EDONE;
	}

	i = j = e = 0;
	fr = FILTER_PASSED;
	/* Use all filters until there is a hard state: either rejection or whitelisting.
	 * Continue on temporary errors to see if a later filter would introduce a hard
	 * rejection to avoid that mail to come back to us just to fail. */
	while ((rcpt_cbs[j] != NULL) && ((fr == FILTER_PASSED) || (fr == FILTER_DENIED_TEMPORARY))) {
		enum config_domain t;

		errmsg = NULL;
		fr = rcpt_cbs[j](&ds, &errmsg, &bt);

		switch (fr) {
		case FILTER_WHITELISTED:
			/* will terminate the loop */
			break;
		case FILTER_PASSED:
			/* test next filter */
			break;
		case FILTER_DENIED_TEMPORARY:
			if (!getsetting(&ds, "fail_hard_on_temp", &t)) {
				e = 1;
				break;
			}
			fr = FILTER_DENIED_UNSPECIFIC;
			/* fallthrough */
		case FILTER_DENIED_UNSPECIFIC:
			if (getsetting(&ds, "nonexist_on_block", &t))
				fr = FILTER_DENIED_NOUSER;
			break;
		case FILTER_ERROR:
			{
				char filterno[ULSTRLEN];
				char errnostr[ULSTRLEN];
				const char *logmess[] = {"error ", errnostr, " in filter ", filterno, " for user ", r->to.s, NULL};

				ultostr(errno, errnostr);
				ultostr(j, filterno);

				log_writen(LOG_WARNING, logmess);
				e = 1;
				fr = FILTER_DENIED_TEMPORARY;
			}
		default:
			assert(filter_denied(fr));
			/* will terminate the loop */
			break;
		}
		j++;
	}
	userconf_free(&ds);

	/* check if there has been a temporary error, but no hard rejection */
	if ((fr == FILTER_PASSED) && e)
		fr = FILTER_DENIED_TEMPORARY;
	if (filter_denied(fr) || (fr == FILTER_ERROR))
		goto userdenied;
	i = 0;

	goodrcpt++;
	r->ok = 1;
	okmsg[1] = r->to.s;

	return net_writen(okmsg) ? errno : 0;
userdenied:
	e = errno;
	if (filter_denied(fr)) {
		if (errmsg != NULL) {
			logmsg[2] = r->to.s;
			logmsg[8] = errmsg;
			logmsg[10] = blocktype[bt];
			if (fr == FILTER_DENIED_TEMPORARY)
				log_writen(LOG_INFO, logmsg);
			else
				log_writen(LOG_INFO, logmsg + 1);
		}
		tarpit();
	}

	switch (fr) {
	case FILTER_ERROR:
		j = 1;
		break;
	case FILTER_DENIED_UNSPECIFIC:
		if ( (j = netwrite("550 5.7.1 mail denied for policy reasons\r\n")) )
			e = errno;
		break;
	case FILTER_DENIED_NOUSER:
		{
			const char *rcptmsg[] = {"550 5.1.1 no such user <", r->to.s, ">", NULL};

			if ( (j = net_writen(rcptmsg)) )
				e = errno;
		}
		break;
	case FILTER_DENIED_TEMPORARY:
		if ( (j = netwrite("450 4.7.0 mail temporary denied for policy reasons\r\n")) )
			e = errno;
		break;
	default:
		assert(filter_denied(fr));
		j = 0;
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
	struct statvfs sbuf;
	const char *okmsg[] = {"250 2.1.5 sender <", NULL, "> is syntactically correct", NULL};
	char *s;
	size_t bugoffset = 0;

	/* detect broken clients that have spaces between ':' and '<' */
	while ((bugoffset < linein.len - 10) && (linein.s[10 + bugoffset] == ' '))
		bugoffset++;
	if (linein.s[10 + bugoffset] != '<')
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

	i = addrparse(linein.s + 11 + bugoffset, 0, &(xmitstat.mailfrom), &more, NULL, rcpthosts, rcpthsize);
	xmitstat.frommx = NULL;
	xmitstat.fromdomain = 0;
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
	if (linein.len > validlength)
		return E2BIG;

	if (statvfs("queue/lock/sendmutex", &sbuf) != 0) {
		int e = errno;

		switch (e) {
		case ENOMEM:
			return e;
		case ENOENT:	/* uncritical: only means that qmail-send is not running */
		case ENOSYS:
		/* will happen in most cases because program runs not in group qmail */
		case EACCES:
			log_write(LOG_WARNING, "warning: can not get free queue disk space");
			break;
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
	} else {
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
		if (xmitstat.fromdomain == DNS_ERROR_LOCAL)
			return errno;
		s = strchr(xmitstat.mailfrom.s, '@') + 1;
	} else {
		xmitstat.fromdomain = 0;
		xmitstat.frommx = NULL;
		s = HELOSTR;
	}

	i = lookupipbl_name(connection_is_ipv4() ? "spffriends" : "spffriends6");
	if (i < 0) {
		return -i;
	} else if (i > 0) {
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
	return netwrite("252 2.1.5 send some mail, I'll do my very best\r\n") ? errno : 0;
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
		queue_reset();
	/* if there was EHLO or HELO before we reset to the state to immediately after this */
	if (comstate >= 0x008) {
		freedata();
		current_command->state = (0x008 << xmitstat.esmtp);
	}
	/* we don't need the else case here: if there was no helo/ehlo no one has changed .state */
	return netwrite("250 2.0.0 ok\r\n") ? errno : 0;
}

int
smtp_quit(void)
{
	const char *msg[] = {"221 2.0.0 ", heloname.s, " service closing transmission channel", NULL};
	int rc;

	rc = net_writen(msg);
	conn_cleanup(rc ? errno : 0);
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
	if (!strncmp(" / HTTP/1.", linein.s + 4, 10)) {
		const char *logmsg[] = {"dropped connection from [", xmitstat.remoteip, "]: client is talking HTTP to me", NULL};
		log_writen(LOG_INFO, logmsg);
		exit(0);
	}
	return EINVAL;
}