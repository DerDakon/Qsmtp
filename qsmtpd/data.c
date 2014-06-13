/** \file data.c
 \brief receive and queue message data
 */
#include <qsmtpd/qsdata.h>

#include <sys/wait.h>
#include <sys/mman.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "netio.h"
#include "log.h"
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/antispam.h>
#include "version.h"
#include "tls.h"
#include "fmt.h"
#include <qsmtpd/syntax.h>

#define MAXHOPS		100		/* maximum number of "Received:" lines allowed in a mail (loop prevention) */

static const char noqueue[] = "451 4.3.2 can not connect to queue\r\n";
static pid_t qpid;			/* the pid of qmail-queue */
unsigned long maxbytes;
static int chunked;			/* set to 1 if BDAT transfer is running */
static char datebuf[35] = ">; ";		/* the date for the From- and Received-lines */
static int queuefd_data = -1;		/**< descriptor to send message data to qmail-queue */
static int queuefd_hdr = -1;		/**< descriptor to send header data to qmail-queue */

static int
err_pipe(void)
{
	log_write(LOG_ERR, "cannot create pipe to qmail-queue");
	return netwrite(noqueue) ? errno : 0;
}

static int
err_fork(void)
{
	log_write(LOG_ERR, "cannot fork qmail-queue");
	return netwrite(noqueue) ? errno : 0;
}

/**
 * reset queue descriptors
 */
void
queue_reset(void)
{
	if (queuefd_data) {
		while (close(queuefd_data) && (errno == EINTR));
		queuefd_data = -1;
	}
	while (close(queuefd_hdr) && (errno == EINTR));
	while ((waitpid(qpid, NULL, 0) == -1) && (errno == EINTR));
}

static int
queue_init(void)
{
	int i;
	const char *qqbin = NULL;
	int fd0[2], fd1[2];		/* the fds to communicate with qmail-queue */

	if (pipe(fd0)) {
		if ( (i = err_pipe()) )
			return i;
		return EDONE;
	}
	if (pipe(fd1)) {
		/* EIO on pipe operations? Shit just happens (although I don't know why this could ever happen) */
		while (close(fd0[0]) && (errno == EINTR));
		while (close(fd0[1]) && (errno == EINTR));
		if ( (i = err_pipe()) )
			return i;
		return EDONE;
	}

	if (is_authenticated_client())
		qqbin = getenv("QMAILQUEUEAUTH");

	if ((qqbin == NULL) || (strlen(qqbin) == 0))
		qqbin = getenv("QMAILQUEUE");

	if ((qqbin == NULL) || (strlen(qqbin) == 0))
			qqbin = "bin/qmail-queue";

	/* DJB uses vfork at this point (qmail.c::open_qmail) which looks broken
	 * because he modifies data before calling execve */
	switch (qpid = fork_clean()) {
	case -1:	if ( (i = err_fork()) )
				return i;
			return EDONE;
	case 0:
			while (close(fd0[1])) {
				if (errno != EINTR)
					_exit(120);
			}
			while (close(fd1[1])) {
				if (errno != EINTR)
					_exit(120);
			}
			if (dup2(fd0[0], 0) == -1)
				_exit(120);
			if (dup2(fd1[0], 1) == -1)
				_exit(120);
			/* no chdir here, we already _are_ there (and qmail-queue does it again) */
			execlp(qqbin, qqbin, NULL);
			_exit(120);
	default:	while (close(fd0[0]) && (errno == EINTR));
			while (close(fd1[0]) && (errno == EINTR));
	}

/* check if the child already returned, which means something went wrong */
	if (waitpid(qpid, NULL, WNOHANG)) {
		/* error here may just happen, we are already in trouble */
		while (close(fd0[1]) && (errno == EINTR));
		while (close(fd1[1]) && (errno == EINTR));
		if ( (i = err_fork()) )
			return i;
		return EDONE;
	}

	queuefd_data = fd0[1];
	queuefd_hdr = fd1[1];

	return 0;
}

static inline void
two_digit(char *buf, int num)
{
	*buf = '0' + (num / 10);
	*(buf + 1) = '0' + (num % 10);
}

/**
 * write RfC822 date information to buffer
 *
 * @param buf buffer to store string in, must have at least 32 bytes free
 *
 * exactly 31 bytes in buffer are filled, it will _not_ be 0-terminated
 */
static void
date822(char *buf)
{
	time_t ti;
	struct tm stm;
	const char *weekday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
	const char *month[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	long tz;

	ti = time(NULL);
	tzset();
	tz = timezone / 60;
	localtime_r(&ti, &stm);
	memcpy(buf, weekday[stm.tm_wday], 3);
	memcpy(buf + 3, ", ", 2);
	two_digit(buf + 5, stm.tm_mday);
	buf[7] = ' ';
	memcpy(buf + 8, month[stm.tm_mon], 3);
	buf[11] = ' ';
	ultostr(1900 + stm.tm_year, buf + 12);
	buf[16] = ' '; /* this will fail after 9999, but that I'll fix then */
	two_digit(buf + 17, stm.tm_hour);
	buf[19] = ':';
	two_digit(buf + 20, stm.tm_min);
	buf[22] = ':';
	two_digit(buf + 23, stm.tm_sec);
	buf[25] = ' ';
	buf[26] = (tz <= 0) ? '+' : '-';
	if (tz < 0)
	    tz = -tz;
	if (stm.tm_isdst > 0) {
		two_digit(buf + 27, 1 + (tz / 60));
	} else {
		two_digit(buf + 27, tz / 60);
	}
	two_digit(buf + 29, tz % 60);
}

#define WRITE(fd,buf,len) \
		do { \
			if ( (rc = write(fd, buf, len)) < 0 ) { \
				return rc; \
			} \
		} while (0)

#define WRITEL(fd, str)		WRITE(fd, str, strlen(str))

static int
queue_header(void)
{
	int rc;
	size_t i = (authhide && is_authenticated_client()) ? 2 : 0;
	/* do not bother that the next two messages are basically the same:
	 * the compiler is usually clever enought to find that out, too */
	const char afterprot[]     =  "\n\tfor <";	/* the string to be written after the protocol */
	const char afterprotauth[] = "A\n\tfor <";	/* the string to be written after the protocol for authenticated mails*/

/* write "Received-SPF: " line */
	if (!is_authenticated_client() && (relayclient != 1)) {
		if ( (rc = spfreceived(queuefd_data, xmitstat.spf)) )
			return rc;
	}
/* write the "Received: " line to mail header */
	WRITEL(queuefd_data, "Received: ");
	if (!i) {
		if (xmitstat.remotehost.len) {
			WRITEL(queuefd_data, "from ");
			WRITE(queuefd_data, xmitstat.remotehost.s, xmitstat.remotehost.len);
		} else {
			WRITEL(queuefd_data, "from unknown");
		}
		WRITEL(queuefd_data, " ([");
		WRITE(queuefd_data, xmitstat.remoteip, strlen(xmitstat.remoteip));
		WRITEL(queuefd_data, "]");
		if (xmitstat.remoteport) {
			WRITEL(queuefd_data, ":");
			WRITEL(queuefd_data, xmitstat.remoteport);
		}
		if (xmitstat.helostr.len) {
			WRITEL(queuefd_data, " HELO ");
			WRITE(queuefd_data, xmitstat.helostr.s, xmitstat.helostr.len);
		}
	}
	if (xmitstat.authname.len) {
		const char authstr[] = ") (auth=";
		WRITE(queuefd_data, authstr + i, strlen(authstr) - i);
		WRITE(queuefd_data, xmitstat.authname.s, xmitstat.authname.len);
	} else if (xmitstat.tlsclient != NULL) {
		const char authstr[] = ") (cert=";
		WRITE(queuefd_data, authstr + i, strlen(authstr) - i);
		WRITEL(queuefd_data, xmitstat.tlsclient);
	} else if (xmitstat.remoteinfo != NULL) {
		WRITEL(queuefd_data, ") (ident=");
		WRITEL(queuefd_data, xmitstat.remoteinfo);
	}
	WRITEL(queuefd_data, ")\n\tby ");
	WRITE(queuefd_data, heloname.s, heloname.len);
	WRITEL(queuefd_data, " (" VERSIONSTRING ") with ");
	if (chunked)
		WRITEL(queuefd_data, "(chunked) ");
	WRITEL(queuefd_data, protocol);
	/* add the 'A' to the end of ESMTP or ESMTPS as described in RfC 3848 */
	if (xmitstat.authname.len != 0) {
		WRITEL(queuefd_data, afterprotauth);
	} else {
		WRITEL(queuefd_data, afterprot);
	}
	WRITE(queuefd_data, head.tqh_first->to.s, head.tqh_first->to.len);
	date822(datebuf + 3);
	datebuf[34] = '\n';
	WRITE(queuefd_data, datebuf, 35);
	return 0;
}

#undef WRITE
#define WRITE(fd,buf,len) \
		do { \
			if ( (rc = write(fd, buf, len)) < 0 ) { \
				goto err_write; \
			} \
		} while (0)

static int
queue_envelope(const unsigned long msgsize)
{
	char s[ULSTRLEN];		/* msgsize */
	char t[ULSTRLEN];		/* goodrcpt */
	char bytes[] = " bytes, ";
	const char *logmail[] = {"received ", "", "", "message ", "", "to <", NULL, "> from <", MAILFROM,
					"> ", "from IP [", xmitstat.remoteip, "] (", s, bytes,
					NULL, " recipients)", NULL};
	char *authmsg = NULL;
	int rc, e;

	if (ssl)
		logmail[1] = "encrypted ";
	if (chunked)
		logmail[2] = "chunked ";
	if (xmitstat.spacebug)
		logmail[4] = "with SMTP space bug ";
	ultostr(msgsize, s);
	if (goodrcpt > 1) {
		ultostr(goodrcpt, t);
		logmail[15] = t;
	} else {
		bytes[6] = ')';
		bytes[7] = '\0';
		/* logmail[14] is already NULL so that logging will stop there */
	}
/* print the authname.s into a buffer for the log message */
	if (xmitstat.authname.len) {
		if (strcasecmp(xmitstat.authname.s, MAILFROM)) {
			authmsg = malloc(xmitstat.authname.len + 23);

			if (!authmsg)
				return errno;
			memcpy(authmsg, "> (authenticated as ", 20);
			memcpy(authmsg + 20, xmitstat.authname.s, xmitstat.authname.len);
			memcpy(authmsg + 20 + xmitstat.authname.len, ") ", 3);
			logmail[9] = authmsg;
		} else {
			logmail[9] = "> (authenticated) ";
		}
	}

/* write the envelope information to qmail-queue */

	/* write the return path to qmail-queue */
	WRITEL(queuefd_hdr, "F");
	WRITE(queuefd_hdr, MAILFROM, xmitstat.mailfrom.len + 1);

	while (head.tqh_first != NULL) {
		struct recip *l = head.tqh_first;

		logmail[6] = l->to.s;
		if (l->ok) {
			const char *at = strchr(l->to.s, '@');

			log_writen(LOG_INFO, logmail);
			WRITEL(queuefd_hdr, "T");
			if (at && (*(at + 1) == '[')) {
				WRITE(queuefd_hdr, l->to.s, at - l->to.s + 1);
				WRITE(queuefd_hdr, liphost.s, liphost.len + 1);
			} else {
				WRITE(queuefd_hdr, l->to.s, l->to.len + 1);
			}
		}
		TAILQ_REMOVE(&head, head.tqh_first, entries);
		free(l->to.s);
		free(l);
	}
	WRITE(queuefd_hdr, "", 1);
err_write:
	e = errno;
	while ( (rc = close(queuefd_hdr)) ) {
		if (errno != EINTR) {
			e = errno;
			break;
		}
	}
	while (head.tqh_first != NULL) {
		struct recip *l = head.tqh_first;

		TAILQ_REMOVE(&head, head.tqh_first, entries);
		free(l->to.s);
		free(l);
	}
	freedata();
	free(authmsg);
	errno = e;
	return rc;
}

static int
queue_result(void)
{
	int status;

	while(waitpid(qpid, &status, 0) == -1) {
		/* don't know why this could ever happen, but we want to be sure */
		if (errno == EINTR) {
			log_write(LOG_ERR, "waitpid(qmail-queue) went wrong");
			return netwrite("451 4.3.2 error while writing mail to queue\r\n") ? errno : EDONE;
		}
	}
	if (WIFEXITED(status)) {
		int exitcode = WEXITSTATUS(status);

		if (!exitcode) {
			return netwrite("250 2.5.0 accepted message for delivery\r\n") ? errno : 0;
		} else {
			char ec[ULSTRLEN];
			const char *logmess[] = {"qmail-queue failed with exitcode ", ec, NULL};
			const char *netmsg;

			ultostr(exitcode, ec);
			log_writen(LOG_ERR, logmess);

			/* stolen from qmail.c::qmail_close */
			switch(exitcode) {
			case 11:
				netmsg = "554 5.1.3 envelope address too long for qq\r\n"; break;
			case 31:
				netmsg = "554 5.3.0 mail server permanently rejected message\r\n"; break;
			case 51:
				netmsg = "451 4.3.0 qq out of memory\r\n"; break;
			case 52:
				netmsg = "451 4.3.0 qq timeout\r\n"; break;
			case 53:
				netmsg = "451 4.3.0 qq write error or disk full\r\n"; break;
			case 54:
				netmsg = "451 4.3.0 qq read error\r\n"; break;
			case 55:
				netmsg = "451 4.3.0 qq unable to read configuration\r\n"; break;
			case 56:
				netmsg = "451 4.3.0 qq trouble making network connection\r\n"; break;
			case 61:
				netmsg = "451 4.3.0 qq trouble in home directory\r\n"; break;
			case 63:
			case 64:
			case 65:
			case 66:
			case 62:
				netmsg = "451 4.3.0 qq trouble creating files in queue\r\n"; break;
			case 71:
				netmsg = "451 4.3.0 mail server temporarily rejected message\r\n"; break;
			case 72:
				netmsg = "451 4.4.1 connection to mail server timed out\r\n"; break;
			case 73:
				netmsg = "451 4.4.1 connection to mail server rejected\r\n"; break;
			case 74:
				netmsg = "451 4.4.2 communication with mail server failed\r\n"; break;
			case 91: /* this happens when the 'F' and 'T' are not correctly sent or understood. */
			case 81:
				netmsg = "451 4.3.0 qq internal bug\r\n"; break;
			default:
				if ((exitcode >= 11) && (exitcode <= 40))
					netmsg = "554 5.3.0 qq permanent problem\r\n";
				else
					netmsg = "451 4.3.0 qq temporary problem\r\n";
			}
			return netwrite(netmsg) ? errno : EDONE;
		}
	} else {
		log_write(LOG_ERR, "WIFEXITED(qmail-queue) went wrong");
		return netwrite("451 4.3.2 error while writing mail to queue\r\n") ? errno : EDONE;
	}
}

/**
 * @brief check if header lines violate RfC822
 * @param headerflags flags which headers were already found
 * @param hdrname the header found on error
 * @return if processing should continue
 * @retval 0 nothing special found
 * @retval 1 a known header was found
 * @retval -2 a duplicate header was found (hdrname is set)
 * @retval -8 unencoded 8 bit data was found
 */
static int
check_rfc822_headers(unsigned int *headerflags, const char **hdrname)
{
	const char *searchpattern[] = { "Date:", "From:", "Message-Id:", NULL };
	int j;

	for (j = linelen - 1; j >= 0; j--) {
		if (linein[j] < 0)
			return -8;
	}

	for (j = 0; searchpattern[j] != NULL; j++) {
		if (!strncasecmp(searchpattern[j], linein, strlen(searchpattern[j]))) {
			if ((*headerflags) & (1 << j)) {
				*hdrname = searchpattern[j];
				return -2;
			} else {
				*headerflags |= (1 << j);
				return 1;
			}
		}
	}

	return 0;
}

static unsigned long msgsize;

/**
 * handle DATA command and store data into queue
 *
 * @return 0 on success, else error code
 */
int
smtp_data(void)
{
	char s[ULSTRLEN];		/* msgsize */
	const char *logmail[] = {"rejected message to <", NULL, "> from <", MAILFROM,
					"> from IP [", xmitstat.remoteip, "] (", s, " bytes) {",
					NULL, NULL, NULL, NULL};
	int i, rc;
	unsigned int headerflags = 0;	/* Date: and From: are required in header,
					 * else message is bogus (RfC 2822, section 3.6).
					 * We also scan for Message-Id here.
					 * RfC 2821 says server SHOULD NOT check for this,
					 * but we let the user decide.*/
#define HEADER_HAS_DATE 0x1
#define HEADER_HAS_FROM 0x2
#define HEADER_HAS_MSGID 0x4
	const char *errmsg = NULL;
	char errbuf[96];			/* for dynamically constructed error messages */
	unsigned int hops = 0;		/* number of "Received:"-lines */

	msgsize = 0;
	chunked = 0;

	if (badbounce || !goodrcpt) {
		tarpit();
		return netwrite("554 5.1.1 no valid recipients\r\n") ? errno : EDONE;
	}

	sync_pipelining();

	if ( (i = queue_init()) )
		return i;

	if (netwrite("354 Start mail input; end with <CRLF>.<CRLF>\r\n")) {
		int e = errno;

		queue_reset();
		return e;
	}
#ifdef DEBUG_IO
	in_data = 1;
#endif

	if ( (rc = queue_header()) )
		goto loop_data;

	/* loop until:
	 * -the message is bigger than allowed
	 * -we reach the empty line between header and body
	 * -we reach the end of the transmission
	 */
	if (net_read())
		goto loop_data;
/* write the data to mail */
	while (!((linelen == 1) && (linein[0] == '.')) && (msgsize <= maxbytes) && linelen && (hops <= MAXHOPS)) {

		if (linein[0] == '.') {
			/* write buffer beginning at [1], we do not have to check if the second character
			 * is also a '.', RfC 2821 says only we should discard the '.' beginning the line */
			WRITE(queuefd_data, linein + 1, linelen - 1);
			msgsize += linelen + 1;
		} else {
			int flagr = 1;	/* if the line may be a "Received:" or "Delivered-To:"-line */

			if ((xmitstat.check2822 & 1) || submission_mode) {
				const char *hdrname;
				switch (check_rfc822_headers(&headerflags, &hdrname)) {
				case 0:
					break;
				case 1:
					flagr = 0;
					break;
				case -2: {
					const char *errtext = "550 5.6.0 message does not comply to RfC2822: "
							"more than one '";

					logmail[9] = "more than one '";
					logmail[10] = hdrname;
					logmail[11] = "' in header}";

					errmsg = errbuf;
					memcpy(errbuf, errtext, strlen(errtext));
					memcpy(errbuf + strlen(errtext), hdrname, strlen(hdrname));
					memcpy(errbuf + strlen(errtext) + strlen(hdrname), "'\r\n", 4);
					goto loop_data;
				}
				case -8:
					logmail[9] = "8bit-character in message header}";
					errmsg = "550 5.6.0 message does not comply to RfC2822: "
							"8bit character in message header\r\n";
					goto loop_data;
				}
			}
			if (flagr) {
				if (!strncasecmp("Received:", linein, 9)) {
					if (++hops > MAXHOPS) {
						logmail[9] = "mail loop}";
						errmsg = "554 5.4.6 too many hops, this message is looping\r\n";
						goto loop_data;
					}
				} else if ((linelen >= 20) && !strncmp("Delivered-To:", linein, 13)) {
					/* we write it exactly this way, noone else is allowed to
					 * change our header lines so we do not need to use strncasecmp
					 *
					 * The minimum length of 21 are a sum of:
					 * 13: Delivered-To:
					 * 1: ' '
					 * 1: at least 1 character localpart
					 * 1: @
					 * 1: at least 1 character domain name
					 * 1: '.'
					 * 2: at least 2 characters top level domain */
					struct recip *np;

					for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
						if (np->ok && !strcmp(linein + 14, np->to.s)) {
							logmail[9] = "mail loop}";
							errmsg = "554 5.4.6 message is looping, found a \"Delivered-To:\" line with one of the recipients\r\n";
							goto loop_data;
						}
					}
				}
			}

			/* write buffer beginning at [0] */
			WRITE(queuefd_data, linein, linelen);
			msgsize += linelen + 2;
		}
		WRITEL(queuefd_data, "\n");
		/* this has to stay here and can't be combined with the net_read before the while loop:
		 * if we combine them we add an extra new line for the line that ends the transmission */
		if (net_read())
			goto loop_data;
	}
	if (submission_mode) {
		if (!(headerflags & HEADER_HAS_DATE)) {
			WRITEL(queuefd_data, "Date: ");
			WRITE(queuefd_data, datebuf + 3, 32);
		}
		if (!(headerflags & HEADER_HAS_FROM)) {
			WRITEL(queuefd_data, "From: <");
			WRITE(queuefd_data, xmitstat.mailfrom.s, xmitstat.mailfrom.len);
			WRITEL(queuefd_data, ">\n");
		}
		if (!(headerflags & HEADER_HAS_MSGID)) {
			char timebuf[20];
			struct timeval ti;
			struct timezone tz = { .tz_minuteswest = 0, .tz_dsttime = 0 };
			size_t l;

			WRITEL(queuefd_data, "Message-Id: <");

			gettimeofday(&ti, &tz);
			ultostr((const unsigned long) ti.tv_sec, timebuf);
			l = strlen(timebuf);
			timebuf[l] = '.';
			ultostr(ti.tv_usec, timebuf + l + 1);
			l += 1 + strlen(timebuf + l + 1);
			WRITE(queuefd_data, timebuf, l);
			WRITEL(queuefd_data, "@");
			WRITE(queuefd_data, msgidhost.s, msgidhost.len);
			WRITEL(queuefd_data, ">\n");
		}
	} else {
		if (xmitstat.check2822 & 1) {
			if (!(headerflags & HEADER_HAS_DATE)) {
				logmail[9] = "no 'Date:' in header}";
				errmsg = "550 5.6.0 message does not comply to RfC2822: 'Date:' missing\r\n";
				goto loop_data;
			} else if (!(headerflags & HEADER_HAS_FROM)) {
				logmail[9] = "no 'From:' in header}";
				errmsg = "550 5.6.0 message does not comply to RfC2822: 'From:' missing\r\n";
				goto loop_data;
			}
		}
	}
	if (!linelen) {
		/* if(linelen) message has no body and we already are at the end */
		WRITEL(queuefd_data, "\n");
		if (net_read())
			goto loop_data;
		while (!((linelen == 1) && (linein[0] == '.')) && (msgsize <= maxbytes)) {
			int offset;

			if ((xmitstat.check2822 & 1) && !xmitstat.datatype) {
				for (i = linelen - 1; i >= 0; i--)
					if (linein[i] < 0) {
						logmail[9] = "8bit-character in message body}";
						errmsg = "550 5.6.0 message contains 8bit characters\r\n";
						goto loop_data;
					}
			}

			offset = (linein[0] == '.') ? 1 : 0;
			WRITE(queuefd_data, linein + offset, linelen - offset);
			msgsize += linelen + 2 - offset;

			WRITEL(queuefd_data, "\n");
			if (net_read())
				goto loop_data;
		}
	}
	if (msgsize > maxbytes) {
		logmail[9] = "message too big}";
		rc = EMSGSIZE;
		errmsg = NULL;
		goto loop_data;
	}
	/* the message body is sent to qmail-queue. Close the file descriptor and send the envelope information */
	while (close(queuefd_data)) {
		if (errno != EINTR)
			goto err_write;
	}
	queuefd_data = -1;
	if (queue_envelope(msgsize))
		goto err_write;

#ifdef DEBUG_IO
	in_data = 0;
#endif
	commands[7].state = (0x008 << xmitstat.esmtp);
	return queue_result();
loop_data:
	rc = errno;
	if (logmail[9] == NULL) {
		switch (rc) {
		case EINVAL:
			logmail[9] = "bad CRLF sequence}";
			errmsg = "500 5.5.2 bad <CRLF> sequence\r\n";
			break;
		case E2BIG:
			logmail[9] = "too long SMTP line}";
			break;
		default:
			logmail[9] = "read error}";
		}
	}
	while (close(queuefd_data) && (errno == EINTR));
	queuefd_data = -1;
	/* eat all data until the transmission ends. But just drop it and return
	 * an error defined before jumping here */
	do {
		msgsize += linelen + 2;
		if (linein[0] == '.')
			msgsize--;
		net_read();
	} while ((linelen != 1) && (linein[0] != '.'));
	while (close(queuefd_hdr) && (errno == EINTR));
	ultostr(msgsize, s);

	while (head.tqh_first != NULL) {
		struct recip *l = head.tqh_first;

		TAILQ_REMOVE(&head, head.tqh_first, entries);
		if (l->ok) {
			logmail[1] = l->to.s;
			log_writen(LOG_INFO, logmail);
		}
		free(l->to.s);
		free(l);
	}
	freedata();

#ifdef DEBUG_IO
	in_data = 0;
#endif
	if (errmsg)
		return netwrite(errmsg) ? errno : EDONE;
	return rc;
err_write:
	rc = errno;
	queue_reset();
	freedata();

/* first check, then read: if the error happens on the last line nothing will be read here */
	while ((linelen != 1) || (linein[0] != '.')) {
		if (net_read())
			break;
	}

#ifdef DEBUG_IO
	in_data = 0;
#endif
	if ((rc == ENOSPC) || (rc == EFBIG)) {
		rc = EMSGSIZE;
	} else if ((errno != ENOMEM) && (errno != EMSGSIZE) && (errno != E2BIG) && (errno != EINVAL)) {
		if (netwrite("451 4.3.0 error writing mail to queue\r\n"))
			return errno;
	}
	switch (rc) {
	case EMSGSIZE:
	case E2BIG:
	case ENOMEM:
		return rc;
	case EPIPE:
		log_write(LOG_ERR, "broken pipe to qmail-queue");
		return EDONE;
	case EINTR:
		log_write(LOG_ERR, "interrupt while writing to qmail-queue");
		return EDONE;
	case EINVAL:	/* This errors happen if client sends invalid data (e.g. bad <CRLF> sequences). */
		return netwrite("500 5.5.2 bad <CRLF> sequence\r\n") ? errno : EBOGUS;
	default:	/* normally none of the other errors may ever occur. But who knows what I'm missing here? */
		{
			const char *logmsg[] = {"error in DATA: ", strerror(rc), NULL};

			log_writen(LOG_ERR, logmsg);
			return EDONE; // will not be caught in main
		}
	}
}

#ifdef CHUNKING
static int bdaterr;
static int lastcr;

/**
 * handle BDAT command and store data into queue
 *
 * @return 0 on success, else error code
 */
int
smtp_bdat(void)
{
	char s[ULSTRLEN];		/* msgsize */
	const char *logmail[] = {"rejected message to <", NULL, "> from <", MAILFROM,
					"> from IP [", xmitstat.remoteip, "] (", s, " bytes) {",
					NULL, NULL};
	int rc;
#warning FIXME: loop detection missing
	unsigned int hops = 0;		/* number of "Received:"-lines */
	long chunksize;
	char *more;

	if (badbounce || !goodrcpt) {
		tarpit();
		return netwrite("554 5.1.1 no valid recipients\r\n") ? errno : EDONE;
	}

	if ((linein[5] < '0') || (linein[5] > '9'))
		return EINVAL;
	chunksize = strtol(linein + 5, &more, 10);
	if ((chunksize < 0) || (*more && (*more != ' ')))
		return EINVAL;
	if (*more && strcasecmp(more + 1, "LAST"))
		return EINVAL;

	if (comstate != 0x0800) {
		msgsize = 0;
		bdaterr = 0;
		comstate = 0x0800;
		chunked = 1;

		bdaterr = queue_init();

		if (!bdaterr && (rc = queue_header()) ) {
			bdaterr = rc;
		}
	}

	while (chunksize > 0) {
		size_t chunk;
		char inbuf[2048];

		if (chunksize >= (long) sizeof(inbuf)) {
			chunk = net_readbin(sizeof(inbuf) - 1, inbuf);
		} else {
			chunk = net_readbin(chunksize, inbuf);
		}
		if (chunk == (size_t) -1) {
			if (!bdaterr) {
				bdaterr = errno;
			}
		} else if (chunk) {
			size_t o;
			size_t offs = 0;

			chunksize -= chunk;
			msgsize += chunk;
			if (lastcr && (inbuf[0] != '\n'))
				WRITEL(queuefd_data, "\r");
			lastcr = (inbuf[chunk - 1] == '\r');

			o = 0;
			while (offs + o < chunk - 1) {
				offs += o;
				do {
					for (; o < chunk; o++)
						if (inbuf[o] == '\r')
							break;
				} while ((o < chunk - 1) && (inbuf[++o] != '\n'));
				if (o != chunk - 1) {
				/* overwrite CR with LF to keep number of writes low
				 * then write it all out */
					inbuf[o - 1] = '\n';
					WRITE(queuefd_data, inbuf + offs, o);
					o++;	/* skip the original LF */
				}
			}

			if (!*more && (inbuf[o] == '\r')) {
				/* keep '\r' in last chunk */
				chunk--;
			}
			WRITE(queuefd_data, inbuf + offs, chunk - offs);
		}
	}

	if ((msgsize > maxbytes) && !bdaterr) {
		logmail[9] = "message too big}";
		while (head.tqh_first != NULL) {
			struct recip *l = head.tqh_first;

			TAILQ_REMOVE(&head, head.tqh_first, entries);
			if (l->ok) {
				logmail[1] = l->to.s;
				log_writen(LOG_INFO, logmail);
			}
			free(l->to.s);
			free(l);
		}
		bdaterr = EMSGSIZE;
	}
	/* send envelope data if this is last chunk */
	if (*more && !bdaterr) {
		/* the message body is sent to qmail-queue. Close the file descriptor and
			* send the envelope information */
		while (close(queuefd_data)) {
			if (errno != EINTR)
				goto err_write;
		}
		queuefd_data = -1;
		if (queue_envelope(msgsize))
			goto err_write;

		commands[11].state = 0x010;
		return queue_result();
	}

	if (bdaterr) {
		if (queuefd_hdr) {
			queue_reset();
			queuefd_hdr = -1;
		}
	} else {
		const char *bdatmess[] = {"250 2.5.0 ", linein + 5, " octets received", NULL};

		bdaterr = net_writen(bdatmess) ? errno : 0;
		chunked = 0;
	}

	return bdaterr;
err_write:
	rc = errno;
	queue_reset();
	freedata();

	if ((rc == ENOSPC) || (rc == EFBIG)) {
		rc = EMSGSIZE;
	} else if ((errno != ENOMEM) && (errno != EMSGSIZE) && (errno != E2BIG)) {
		if (netwrite("451 4.3.0 error writing mail to queue\r\n"))
			return errno;
	}
	switch (rc) {
	case EMSGSIZE:
	case ENOMEM:
		return rc;
	case EPIPE:
		log_write(LOG_ERR, "broken pipe to qmail-queue");
		return EDONE;
	case EINTR:
		log_write(LOG_ERR, "interrupt while writing to qmail-queue");
		return EDONE;
	case E2BIG:
		return rc;
	default: 	/* normally none of the other errors may ever occur. But who knows what I'm missing here? */
		{
			const char *logmsg[] = {"error in BDAT: ", strerror(rc), NULL};

			log_writen(LOG_ERR, logmsg);
			return EDONE; // will not be caught in main
		}
	}
}
#endif
