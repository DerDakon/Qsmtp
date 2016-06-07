/** \file data.c
 \brief receive and queue message data
 */

#include <qsmtpd/qsdata.h>

#include <fmt.h>
#include <log.h>
#include <netio.h>
#include <qsmtpd/antispam.h>
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/queue.h>
#include <qsmtpd/syntax.h>
#include <tls.h>
#include <version.h>

#include <errno.h>
#include <openssl/ssl.h>
#include <string.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define MAXHOPS		100		/* maximum number of "Received:" lines allowed in a mail (loop prevention) */

size_t maxbytes;			/* the maximum allowed size of message data */
static char datebuf[35] = ">; ";		/* the date for the From- and Received-lines */

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

#define WRITE(buf,len) \
		do { \
			if ( (rc = write(queuefd_data, buf, len)) < 0 ) { \
				return rc; \
			} \
		} while (0)

#define WRITEL(str)		WRITE(str, strlen(str))

/**
 * @brief write Received header line
 * @param chunked if message was transferred using BDAT
 */
static int
write_received(const int chunked)
{
	/* There are several cases in this functions where 2 strings are used
	 * where one string is exactly the begin or end of the other. For
	 * code clarity those are both spelled out. The compiler will usually
	 * find this out anyway and will allocate space only for one of them,
	 * and hopefully merge both code paths and use an offset or something
	 * like that. */
	int rc;
	size_t i = (authhide && is_authenticated_client()) ? 1 : 0;
	const char afterprot[]     =  "\n\tfor <";	/* the string to be written after the protocol */
	const char afterprotauth[] = "A\n\tfor <";	/* the string to be written after the protocol for authenticated mails*/

	/* write "Received-SPF: " line */
	if (!is_authenticated_client() && (relayclient != 1)) {
		if ( (rc = spfreceived(queuefd_data, xmitstat.spf)) )
			return rc;
	}
	/* write the "Received: " line to mail header */
	WRITEL("Received: from ");
	if (xmitstat.remotehost.len && !authhide)
		WRITE(xmitstat.remotehost.s, xmitstat.remotehost.len);
	else
		WRITEL("unknown");

	if (!i) {
		WRITEL(" ([");
		WRITE(xmitstat.remoteip, strlen(xmitstat.remoteip));
		if (xmitstat.remoteport) {
			WRITEL("]:");
			WRITEL(xmitstat.remoteport);
		} else {
			WRITEL("]");
		}
		if (xmitstat.helostr.len) {
			WRITEL(" HELO ");
			WRITE(xmitstat.helostr.s, xmitstat.helostr.len);
		}
	}
	if (xmitstat.authname.len) {
		const char authstr[] = ") (auth=";
		WRITEL(authstr + i);
		WRITE(xmitstat.authname.s, xmitstat.authname.len);
	} else if (xmitstat.tlsclient != NULL) {
		const char authstr[] = ") (cert=";
		WRITEL(authstr + i);
		WRITEL(xmitstat.tlsclient);
	} else if ((xmitstat.remoteinfo != NULL) && !i) {
		WRITEL(") (ident=");
		WRITEL(xmitstat.remoteinfo);
	}
	WRITEL(")\n\tby ");
	WRITE(heloname.s, heloname.len);
	WRITEL(" (" VERSIONSTRING ") with ");
	if (!xmitstat.esmtp) {
		WRITEL("SMTP");
	} else if (!ssl) {
		if (chunked)
			WRITEL("(chunked) ESMTP");
		else
			WRITEL("ESMTP");
	} else {
		const char *cipher = SSL_get_cipher(ssl);
		if (chunked)
			WRITEL("(chunked ");
		else
			WRITEL("(");
		/* avoid trouble in case SSL returns a NULL string */
		if (cipher)
			WRITEL(cipher);
		WRITEL(" encrypted) ESMTPS");
	}
	/* add the 'A' to the end of ESMTP or ESMTPS as described in RfC 3848 */
	if (xmitstat.authname.len != 0) {
		WRITEL(afterprotauth);
	} else {
		WRITEL(afterprot);
	}
	WRITE(TAILQ_FIRST(&head)->to.s, TAILQ_FIRST(&head)->to.len);
	date822(datebuf + 3);
	datebuf[34] = '\n';
	WRITE(datebuf, 35);
	return 0;
}

#undef WRITE
#define WRITE(buf, len) \
		do { \
			if ( (rc = write(queuefd_data, buf, len)) < 0 ) { \
				goto err_write; \
			} \
		} while (0)

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

	for (j = linein.len - 1; j >= 0; j--) {
		if (linein.s[j] < 0)
			return -8;
	}

	for (j = 0; searchpattern[j] != NULL; j++) {
		if (!strncasecmp(searchpattern[j], linein.s, strlen(searchpattern[j]))) {
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

	if ( (rc = write_received(0)) )
		goto loop_data;

	/* loop until:
	 * -the message is bigger than allowed
	 * -we reach the empty line between header and body
	 * -we reach the end of the transmission
	 */
	if (net_read(1))
		goto loop_data;
	/* write the data to mail */
	while (!((linein.len == 1) && (linein.s[0] == '.')) && (msgsize <= maxbytes) && (linein.len > 0) && (hops <= MAXHOPS)) {
		if (linein.s[0] == '.') {
			/* write buffer beginning at [1], we do not have to check if the second character
			 * is also a '.', RfC 2821 says only we should discard the '.' beginning the line */
			WRITE(linein.s + 1, linein.len - 1);
			msgsize += linein.len + 1;
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
				if (!strncasecmp("Received:", linein.s, 9)) {
					if (++hops > MAXHOPS) {
						logmail[9] = "mail loop}";
						errmsg = "554 5.4.6 too many hops, this message is looping\r\n";
						goto loop_data;
					}
				} else if ((linein.len >= 20) && !strncmp("Delivered-To:", linein.s, 13)) {
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

					TAILQ_FOREACH(np, &head, entries) {
						if (np->ok && !strcmp(linein.s + 14, np->to.s)) {
							logmail[9] = "mail loop}";
							errmsg = "554 5.4.6 message is looping, found a \"Delivered-To:\" line with one of the recipients\r\n";
							goto loop_data;
						}
					}
				}
			}

			/* write buffer beginning at [0] */
			WRITE(linein.s, linein.len);
			msgsize += linein.len + 2;
		}
		WRITEL("\n");
		/* this has to stay here and can't be combined with the net_read before the while loop:
		 * if we combine them we add an extra new line for the line that ends the transmission */
		if (net_read(1))
			goto loop_data;
	}
	if (submission_mode) {
		if (!(headerflags & HEADER_HAS_DATE)) {
			WRITEL("Date: ");
			WRITE(datebuf + 3, 32);
		}
		if (!(headerflags & HEADER_HAS_FROM)) {
			WRITEL("From: <");
			WRITE(xmitstat.mailfrom.s, xmitstat.mailfrom.len);
			WRITEL(">\n");
		}
		if (!(headerflags & HEADER_HAS_MSGID)) {
			char timebuf[20];
			struct timeval ti;
			struct timezone tz = { .tz_minuteswest = 0, .tz_dsttime = 0 };
			size_t l;

			WRITEL("Message-Id: <");

			gettimeofday(&ti, &tz);
			ultostr((const unsigned long) ti.tv_sec, timebuf);
			l = strlen(timebuf);
			timebuf[l] = '.';
			ultostr(ti.tv_usec, timebuf + l + 1);
			l += 1 + strlen(timebuf + l + 1);
			WRITE(timebuf, l);
			WRITEL("@");
			WRITE(msgidhost.s, msgidhost.len);
			WRITEL(">\n");
		}
	} else if (xmitstat.check2822 & 1) {
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

	if (linein.len == 0) {
		/* if(linelen) message has no body and we already are at the end */
		WRITEL("\n");
		if (net_read(1))
			goto loop_data;
		while (!((linein.len == 1) && (linein.s[0] == '.')) && (msgsize <= maxbytes)) {
			int offset;

			if ((xmitstat.check2822 & 1) && !xmitstat.datatype) {
				for (i = linein.len - 1; i >= 0; i--)
					if (linein.s[i] < 0) {
						logmail[9] = "8bit-character in message body}";
						errmsg = "550 5.6.0 message contains 8bit characters\r\n";
						goto loop_data;
					}
			}

			offset = (linein.s[0] == '.') ? 1 : 0;
			WRITE(linein.s + offset, linein.len - offset);
			msgsize += linein.len + 2 - offset;

			WRITEL("\n");
			if (net_read(1))
				goto loop_data;
		}
	}
	if (msgsize > maxbytes) {
		logmail[9] = "message too big}";
		errno = EMSGSIZE;
		errmsg = NULL;
		goto loop_data;
	}

#ifdef DEBUG_IO
	in_data = 0;
#endif

	if (!queue_envelope(msgsize, 0))
		return queue_result();

err_write:
	rc = errno;
	queue_reset();
	freedata();

/* first check, then read: if the error happens on the last line nothing will be read here */
	while ((linein.len != 1) || (linein.s[0] != '.')) {
		if (net_read(1))
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
		break;
	case EPIPE:
		log_write(LOG_ERR, "broken pipe to qmail-queue");
		rc = EDONE;
		break;
	case EINVAL:	/* This errors happen if client sends invalid data (e.g. bad <CRLF> sequences). */
		return netwrite("500 5.5.2 bad <CRLF> sequence\r\n") ? errno : EBOGUS;
	default:	/* normally none of the other errors may ever occur. But who knows what I'm missing here? */
		{
			const char *logmsg[] = {"error in DATA: ", strerror(rc), NULL};

			log_writen(LOG_ERR, logmsg);
			rc = EDONE; // will not be caught in main
		}
	}

	return rc;
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
	close(queuefd_data);
	queuefd_data = -1;
	/* eat all data until the transmission ends. But just drop it and return
	 * an error defined before jumping here */
	do {
		msgsize += linein.len + 2;
		if (linein.s[0] == '.')
			msgsize--;
		net_read(1);
	} while ((linein.len != 1) || (linein.s[0] != '.'));
	close(queuefd_hdr);
	ultostr(msgsize, s);

	while (!TAILQ_EMPTY(&head)) {
		struct recip *l = TAILQ_FIRST(&head);

		TAILQ_REMOVE(&head, TAILQ_FIRST(&head), entries);
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

	if ((linein.s[5] < '0') || (linein.s[5] > '9'))
		return EINVAL;
	chunksize = strtol(linein.s + 5, &more, 10);
	if ((chunksize < 0) || (*more && (*more != ' ')))
		return EINVAL;
	if (*more && strcasecmp(more + 1, "LAST"))
		return EINVAL;

	if (comstate != 0x0800) {
		msgsize = 0;
		bdaterr = 0;
		comstate = 0x0800;

		bdaterr = queue_init();

		if (!bdaterr && (rc = write_received(1)) ) {
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
				WRITEL("\r");
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
					WRITE(inbuf + offs, o);
					o++;	/* skip the original LF */
				}
			}

			if (!*more && (inbuf[o] == '\r')) {
				/* keep '\r' in last chunk */
				chunk--;
			}
			WRITE(inbuf + offs, chunk - offs);
		}
	}

	if ((msgsize > maxbytes) && !bdaterr) {
		logmail[9] = "message too big}";
		while (!TAILQ_EMPTY(&head)) {
			struct recip *l = TAILQ_FIRST(&head);

			TAILQ_REMOVE(&head, TAILQ_FIRST(&head), entries);
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
		if (queue_envelope(msgsize, 1))
			goto err_write;

		return queue_result();
	}

	if (bdaterr) {
		if (queuefd_hdr >= 0) {
			queue_reset();
			queuefd_hdr = -1;
		}
	} else {
		const char *bdatmess[] = {"250 2.5.0 ", linein.s + 5, " octets received", NULL};

		bdaterr = net_writen(bdatmess) ? errno : 0;
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
