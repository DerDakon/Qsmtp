/** @file queue.c
 * @brief functions for communication with qmail-queue
 */

#include <qsmtpd/antispam.h>
#include <qsmtpd/queue.h>
#include <qsmtpd/qsmtpd.h>
#include <fmt.h>
#include <log.h>
#include <netio.h>
#include <sstring.h>
#include <tls.h>

#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const char noqueue[] = "451 4.3.2 can not connect to queue\r\n";
static pid_t qpid;			/* the pid of qmail-queue */
int queuefd_data = -1;			/**< descriptor to send message data to qmail-queue */
int queuefd_hdr = -1;			/**< descriptor to send header data to qmail-queue */

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
 * @brief reset queue descriptors
 */
void
queue_reset(void)
{
	if (queuefd_data >= 0) {
		while (close(queuefd_data) && (errno == EINTR));
		queuefd_data = -1;
	}
	while (close(queuefd_hdr) && (errno == EINTR));
	while ((waitpid(qpid, NULL, 0) == -1) && (errno == EINTR));
}

int
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

#define WRITE(buf, len) \
		do { \
			if ( (rc = write(queuefd_hdr, buf, len)) < 0 ) { \
				goto err_write; \
			} \
		} while (0)

/**
 * @brief write the envelope data to qmail-queue and syslog
 * @param msgsize size of the received message in bytes
 * @param chunked if message was transferred using BDAT
 */
int
queue_envelope(const unsigned long msgsize, const int chunked)
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
	WRITE("F", 1);
	WRITE(MAILFROM, xmitstat.mailfrom.len + 1);

	while (head.tqh_first != NULL) {
		struct recip *l = head.tqh_first;

		logmail[6] = l->to.s;
		if (l->ok) {
			const char *at = strchr(l->to.s, '@');

			log_writen(LOG_INFO, logmail);
			WRITE("T", 1);
			if (at && (*(at + 1) == '[')) {
				WRITE(l->to.s, at - l->to.s + 1);
				WRITE(liphost.s, liphost.len + 1);
			} else {
				WRITE(l->to.s, l->to.len + 1);
			}
		}
		TAILQ_REMOVE(&head, head.tqh_first, entries);
		free(l->to.s);
		free(l);
	}
	WRITE("", 1);
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

int
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
