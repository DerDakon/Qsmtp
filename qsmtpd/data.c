#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "netio.h"
#include "log.h"
#include "qsmtpd.h"
#include "antispam.h"
#include "version.h"
#include "tls.h"

#define MAXHOPS		100		/* maximum number of "Received:" lines allowed in a mail (loop prevention) */

static const char *noqueue = "451 4.3.2 can not connect to queue\r\n";
static int fd0[2], fd1[2];		/* the fds to communicate with qmail-queue */
static pid_t qpid;

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

static int
queue_init(void)
{
	int i;

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

	/* DJB uses vfork at this point (qmail.c::open_qmail) which looks broken
	 * because he modifies data before calling execve */
	switch (qpid = fork()) {
		case -1:	if ( (i = err_fork()) )
					return i;
				return EDONE;
		case 0:		if (1) {
					char *qqbin;

					qqbin = getenv("QMAILQUEUE");
					if (!qqbin) {
						qqbin = "bin/qmail-queue";
					}
					while ( (i = close(fd0[1])) ) {
						if (errno != EINTR)
							_exit(120);
					}
					while ( (i = close(fd1[1])) ) {
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
				}
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
	return 0;
}

#define WRITE(fd,buf,len)	if ( (rc = write(fd, buf, len)) < 0 ) \
					return rc

static int
queue_header(int fd)
{
	int rc;
	char datebuf[32];		/* the date for the Received-line */
	time_t ti;
	int i;

/* write the "Received: " line to mail header */
	WRITE(fd, "Received: from ", 15);
	if (xmitstat.remotehost.s) {
		WRITE(fd, xmitstat.remotehost.s, xmitstat.remotehost.len);
	} else {
		WRITE(fd, "unknown", 7);
	}
	WRITE(fd, " ([", 3);
	WRITE(fd, xmitstat.remoteip, strlen(xmitstat.remoteip));
	WRITE(fd, "]", 1);
	if (xmitstat.helostr.len) {
		WRITE(fd, " HELO ", 6);
		WRITE(fd, xmitstat.helostr.s, xmitstat.helostr.len);
	}
	WRITE(fd, ")", 1);
	if (xmitstat.authname.len) {
		WRITE(fd, " (auth=", 7);
		WRITE(fd, xmitstat.authname.s, xmitstat.authname.len);
		WRITE(fd, ")", 1);
	} else if (xmitstat.remoteinfo) {
		WRITE(fd, " (", 2);
		WRITE(fd, xmitstat.remoteinfo, strlen(xmitstat.remoteinfo));
		WRITE(fd, ")", 1);
	}
	WRITE(fd, "\n\tby ", 5);
	WRITE(fd, heloname.s, heloname.len);
	WRITE(fd, " (" VERSIONSTRING ")", 3 + strlen(VERSIONSTRING));
	WRITE(fd, " with ", 6);
	WRITE(fd, protocol, strlen(protocol));
	WRITE(fd, "\n\tfor <", 7);
	WRITE(fd, head.tqh_first->to.s, head.tqh_first->to.len);
	WRITE(fd, ">; ", 3);
	ti = time(NULL);
	i = strftime(datebuf, sizeof(datebuf), "%a, %d %b %Y %H:%M:%S %z", localtime(&ti));
	WRITE(fd, datebuf, i);
	WRITE(fd, "\n", 1);
/* write "Received-SPF: " line */
	if (!(xmitstat.authname.len || xmitstat.tlsclient)) {
		if ( (rc = spfreceived(fd, xmitstat.spf)) )
			return rc;
	}
	return 0;
}

#undef WRITE
#define WRITE(fd,buf,len)	if ( (rc = write(fd, buf, len)) < 0 ) \
					goto err_write

static int
queue_envelope(int fd, const unsigned long msgsize)
{
	char *s = NULL;			/* msgsize */
	char *t = NULL;			/* goodrcpt */
	char bytes[] = " bytes, ";
	const char *logmail[] = {"received ", "", "message to <", NULL, "> from <", xmitstat.mailfrom.s,
					"> ", "", "from ip [", xmitstat.remoteip, "] (", NULL, bytes,
					NULL, " recipients)", NULL};
	char *authmsg = NULL;
	int rc;

	if (ssl)
		logmail[1] = "encrypted ";
	s = ultostr(msgsize);
	if (!s)
		s = "unknown";
	logmail[11] = s;
	logmail[5] = xmitstat.mailfrom.len ? xmitstat.mailfrom.s : "";
	if (head.tqh_first == *head.tqh_last) {
		t = ultostr(goodrcpt);
		if (!t)
			t = "unknown";
		logmail[13] = t;
	} else {
		bytes[6] = ')';
		bytes[7] = '\0';
		/* logmail[13] is already NULL so that logging will stop here */
	}
/* print the authname.s into a buffer for the log message */
	if (xmitstat.authname.len) {
		if (strcasecmp(xmitstat.authname.s, xmitstat.mailfrom.s)) {
			authmsg = malloc(xmitstat.authname.len + 21);

			if (!authmsg)
				return errno;
			memcpy(authmsg, "(authenticated as ", 18);
			memcpy(authmsg + 18, xmitstat.authname.s, xmitstat.authname.len);
			memcpy(authmsg + 18 + xmitstat.authname.len, ") ", 3);
			logmail[7] = authmsg;
		} else {
			logmail[7] = "(authenticated) ";
		}
	}

/* write the envelope information to qmail-queue */

	/* write the return path to qmail-queue */
	WRITE(fd, "F", 1);
	WRITE(fd, xmitstat.mailfrom.s, xmitstat.mailfrom.len + 1);

	while (head.tqh_first != NULL) {
		struct recip *l = head.tqh_first;

		logmail[3] = l->to.s;
		if (l->ok) {
			log_writen(LOG_INFO, logmail);
			WRITE(fd, "T", 1);
			WRITE(fd, l->to.s, l->to.len + 1);
		}
		TAILQ_REMOVE(&head, head.tqh_first, entries);
		free(l->to.s);
		free(l);
	}
	WRITE(fd, "", 1);
	while ( (rc = close(fd)) ) {
		if (errno != EINTR) {
			goto err_write;
		}
	}
	if (s[0] != 'u')
		free(s);
	if (logmail[13] && (t[0] != 'u'))
		free(t);

	rc = 0;
err_write:
	freedata();
	free(authmsg);
	return rc;
}

int
smtp_data(void)
{
	const char *logmail[] = {"rejected message to <", NULL, "> from <", xmitstat.mailfrom.s,
					"> from ip [", xmitstat.remoteip, "] (", NULL, " bytes) {",
					NULL, NULL};
	int i, status, rc;
	unsigned long msgsize = 0, maxbytes;
	int fd;
	int flagdate = 0, flagfrom = 0;	/* Date: and From: are required in header,
					 * else message is bogus (RfC 2822, section 3.6).
					 * RfC 2821 says server SHOULD NOT check for this,
					 * but we let the user decide */
	const char *errmsg = NULL;
	unsigned int hops = 0;		/* number of "Received:"-lines */
	char *s = NULL;			/* msgsize */

	if (badbounce || !goodrcpt) {
		tarpit();
		return netwrite("554 5.1.1 no valid recipients\r\n") ? errno : EINVAL;
	}

	if ( (i = queue_init()) )
		return i;

	if ((rc = hasinput())) {
		return rc;

	if (netwrite("354 Start mail input; end with <CRLF>.<CRLF>\r\n"))
		return errno;
	if (databytes) {
		maxbytes = databytes;
	} else {
		maxbytes = -1UL - 1000;
	}

	/* fd is now the file descriptor we are writing to. This is better than always
	 * calculating the offset to fd0[1] */
	fd = fd0[1];
	if ( (rc = queue_header(fd)) )
		goto err_write;

	/* loop until:
	 * -the message is bigger than allowed
	 * -we reach the empty line between header and body
	 * -we reach the end of the transmission
	 */
	if ( (i = net_read()) )
		return errno;
/* write the data to mail */
	while (!((linelen == 1) && (linein[0] == '.')) && (msgsize <= maxbytes) && linelen && (hops <= MAXHOPS)) {

		if (linein[0] == '.') {
			/* write buffer beginning at [1], we do not have to check if the second character 
			 * is also a '.', RfC 2821 says only we should discard the '.' beginning the line */
			WRITE(fd, linein + 1, linelen - 1);
			msgsize += linelen + 1;
		} else {
			int flagr = 1;	/* if the line may be a "Received:" or "Delivered-To:"-line */

			if (xmitstat.check2822 & 1) {
				if (!strncasecmp("Date:", linein, 5)) {
					if (flagdate) {
						logmail[9] = "more than one 'Date:' in header}";
						errmsg = "550 5.6.0 message does not comply to RfC2822: "
								"more than one 'Date:'\r\n";
						goto loop_data;
					} else {
						flagdate = 1;
						flagr = 0;
					}
				} else if (!strncasecmp("From:", linein, 5)) {
					if (flagfrom) {
						logmail[9] = "more than one 'From:' in header}";
						errmsg = "550 5.6.0 message does not comply to RfC2822: "
								"more than one 'From:'\r\n";
						goto loop_data;
					} else {
						flagfrom = 1;
						flagr = 0;
					}
				}
				for (i = linelen - 1; i >= 0; i--) {
					if (linein[i] < 0) {
						logmail[9] = "8bit-character in message header}";
						errmsg = "550 5.6.0 message does not comply to RfC2822: "
								"8bit character in message header\r\n";
						goto loop_data;
					}
				}
			}
			if (flagr) {
				if (!strncasecmp("Received:", linein, 9)) {
					if (++hops > MAXHOPS) {
						logmail[9] = "mail loop}";
						errmsg = "554 5.4.6 too many hops, this message is looping\r\n";
						goto loop_data;
					}
				} else if ((linelen > 20) && !strncmp("Delivered-To:", linein, 13)) {
					/* we write it exactly this way, noone else is allowed to
					 * change our header lines so we do not need to use strncasecmp
					 *
					 * The minimum length of 21 are a sum of:
					 * 13: Delivered-To:
					 * 1: ' '
					 * 1: at least 1 character localpart
					 * 1: @
					 * 2: at least 2 characters domain name
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
			WRITE(fd, linein, linelen);
			msgsize += linelen + 2;
		}
		WRITE(fd, "\n", 1);
		/* this has to stay here and can't be combined with the net_read before the while loop:
		 * if we combine them we add an extra new line for the line that ends the transmission */
		if ( (i = net_read()) )
			return errno;
	}
	if (xmitstat.check2822 & 1) {
		if (!flagdate) {
			logmail[9] = "no 'Date:' in header}";
			errmsg = "550 5.6.0 message does not comply to RfC2822: 'Date:' missing\r\n";
			goto loop_data;
		} else if (!flagfrom) {
			logmail[9] = "no 'From:' in header}";
			errmsg = "550 5.6.0 message does not comply to RfC2822: 'From:' missing\r\n";
			goto loop_data;
		}
	}
	if (!linelen) {
		/* if(linelen) message has no body and we already are at the end */
		WRITE(fd, "\n", 1);
		if ( (i = net_read()) )
			return errno;
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
			WRITE(fd, linein + offset, linelen - offset);
			msgsize += linelen + 2 - offset;

			WRITE(fd, "\n", 1);
			if ( (i = net_read()) )
				return errno;
		}
	}
	if (msgsize > maxbytes) {
		rc = EMSGSIZE;
		errmsg = NULL;
		goto loop_data;
	}
	/* the message body is sent to qmail-queue. Close the file descriptor and send the envelope information */
	while (close(fd)) {
		if (errno != EINTR)
			goto err_write;
	}
	fd0[1] = 0;
	fd = fd1[1];
	if ( (rc = queue_envelope(fd, msgsize)) )
		return rc;

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
			if (netwrite("250 2.5.0 accepted message for delivery\r\n")) {
				return errno;
			} else {
				commands[7].state = (0x008 << xmitstat.esmtp);
				return 0;
			}
		} else {
			const char *logmess[] = {"qmail-queue failed with exitcode ", NULL, NULL};
			const char *netmsg;
			char *ec = ultostr(exitcode);

			logmess[1] = ec ? ec : "unknown";
			log_writen(LOG_ERR, logmess);
			if (ec[0] != 'u')
				free(ec);
 
			/* stolen from qmail.c::qmail_close */
			switch(exitcode) {
				case 11: netmsg = "554 5.1.3 envelope address too long for qq\r\n"; break;
				case 31: netmsg = "554 5.3.0 mail server permanently rejected message\r\n"; break;
				case 51: netmsg = "451 4.3.0 qq out of memory\r\n"; break;
				case 52: netmsg = "451 4.3.0 qq timeout\r\n"; break;
				case 53: netmsg = "451 4.3.0 qq write error or disk full\r\n"; break;
				case 54: netmsg = "451 4.3.0 qq read error\r\n"; break;
/*				case 55: netmsg = "451 4.3.0 qq unable to read configuration\r\n"; break;*/
/*				case 56: netmsg = "451 4.3.0 qq trouble making network connection\r\n"; break;*/
				case 61: netmsg = "451 4.3.0 qq trouble in home directory\r\n"; break;
				case 63:
				case 64:
				case 65:
				case 66:
				case 62: netmsg = "451 4.3.0 qq trouble creating files in queue\r\n"; break;
/*				case 71: netmsg = "451 4.3.0 mail server temporarily rejected message\r\n"; break;
				case 72: netmsg = "451 4.4.1 connection to mail server timed out\r\n"; break;
				case 73: netmsg = "451 4.4.1 connection to mail server rejected\r\n"; break;
				case 74: netmsg = "451 4.4.2 communication with mail server failed\r\n"; break;*/
				case 91: /* this happens when the 'F' and 'T' are not correctly sent.
					  * This is either a bug in qq but most probably a bug here */
				case 81: netmsg = "451 4.3.0 qq internal bug\r\n"; break;
				default:
					if ((exitcode >= 11) && (exitcode <= 40))
						netmsg = "554 5.3.0 qq permanent problem\r\n";
				else
					netmsg = "451 4.3.0 qq temporary problem\r\n";
			}
			return netwrite(netmsg) ? errno : 0;
		}
	} else {
		log_write(LOG_ERR, "WIFEXITED(qmail-queue) went wrong");
		return netwrite("451 4.3.2 error while writing mail to queue\r\n") ? errno : EDONE;
	}
loop_data:
	while (close(fd1[1]) && (errno == EINTR));
	while (close(fd0[1]) && (errno == EINTR));
	/* eat all data until the transmission ends. But just drop it and return
	 * an error defined before jumping here */
	do {
		msgsize += linelen + 2;
		if (linein[0] == '.')
		    msgsize--;
		if (net_read()) {
			int e = errno;

			freedata();
			return e;
		}
	} while ((linelen != 1) && (linein[0] != '.'));
	s = ultostr(msgsize);
	if (!s)
		s = "unknown";
	logmail[7] = s;

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
	if (s[0] != 'u')
		free(s);
	freedata();

	if (errmsg)
		return netwrite(errmsg) ? errno : EDONE;
	return rc;
err_write:
	rc = errno;
	free(s);
	if (fd0[1]) {
		while (close(fd0[1]) && (errno == EINTR));
	}
	while (close(fd1[1]) && (errno == EINTR));
	freedata();
	if (netwrite("451 4.3.0 error writing mail to queue\r\n"))
		return errno;
	switch (rc) {
		case ENOMEM:	return rc;
		case ENOSPC:
		case EFBIG:	return EMSGSIZE;
		case EPIPE:	log_write(LOG_ERR, "broken pipe to qmail-queue");
				return EDONE;
		case EINTR:	log_write(LOG_ERR, "interrupt while writing to qmail-queue");
				return EDONE;
		/* normally none of the other errors may ever occur. But who knows what I'm missing here? */
		default:	return EBADFD; // will not be caught in main
	}
}

