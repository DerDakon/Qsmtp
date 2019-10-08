/** \file conn.c
 \brief functions for establishing connection to remote SMTP server
 */

#include <qremote/conn.h>

#include <log.h>
#include <netio.h>
#include <qdns.h>
#include <qremote/client.h>
#include <qremote/greeting.h>
#include <qremote/qremote.h>
#include <qremote/starttlsr.h>
#include <qdns_dane.h>

#include <errno.h>
#include <syslog.h>
#include <unistd.h>

/**
 * @brief send QUIT to the remote server if there still is a connection
 * @param error the negative error code of the last message
 */
static void
quitmsg_if_net(const int error)
{
	switch (error) {
	case -EPIPE:
	case -ECONNRESET:
	case -ETIMEDOUT:
		close(socketd);
		socketd = -1;
		break;
	default:
		quitmsg();
		break;
	}
}

static void
connection_died(void)
{
	const char *logmsg[] = { "connection to ", rhost, " died", NULL };

	close(socketd);
	socketd = -1;
	log_writen(LOG_WARNING, logmsg);
}

int
connect_mx(struct ips *mx, const struct in6_addr *outip4, const struct in6_addr *outip6)
{
	struct daneinfo *d = NULL;
	int tlsa = 0;
	/* for all MX entries we got: try to enable connection, check if the SMTP server wants us
	 * (sends 220 response) and EHLO/HELO succeeds. If not, try next. If none left, exit. */
	do {
		int flagerr = 0;
		if (tlsa > 0) {
			daneinfo_free(d, tlsa);
			d = NULL;
		}

		/* query DNS before opening the socket, otherwise a long DNS timeout could lead to SMTP
		 * socket timeout */
		tlsa = (mx->name == NULL) ? 0 : dnstlsa(mx->name, targetport, &d);

		socketd = tryconn(mx, outip4, outip6);
		if (socketd < 0) {
			daneinfo_free(d, tlsa);
			return socketd;
		}
		if (dup2(socketd, 0) < 0) {
			daneinfo_free(d, tlsa);
			net_conn_shutdown(shutdown_abort);
		}

		int s = netget(0);
		if (s < 0) {
			switch (-s) {
			case ECONNRESET:
				/* try next MX */
				connection_died();
				continue;
			case EINVAL:
				{
				const char *dropmsg[] = { "invalid greeting from ", rhost, NULL };

				log_writen(LOG_WARNING, dropmsg);
				quitmsg();
				continue;
				}
			default:
				/* something unexpected went wrong, assume that this is a local
				 * problem that will eventually go away. */
				daneinfo_free(d, tlsa);
				net_conn_shutdown(shutdown_abort);
			}
		}

		/* consume the rest of the replies */
		while (linein.s[3] == '-') {
			int t = netget(0);

			if (t == -ECONNRESET) {
				s = t;
				break;
			}

			flagerr |= (s != t);
			if (t > 0)
				continue;

			/* save t, it may be an error code */
			s = t;
			/* if the reply was invalid in itself (i.e. parse error or such)
			 * we can't know what the remote server will do next, so break out
			 * and immediately send quit. Since the initial result of netget()
			 * must have been positive flagerr will always be set here. */
			break;
		}
		if (s == -ECONNRESET) {
			connection_died();
			continue;
		}
		if ((s != 220) || (flagerr != 0)) {
			if (flagerr) {
				const char *dropmsg[] = {"invalid greeting from ", rhost, NULL};

				log_writen(LOG_WARNING, dropmsg);
			}

			quitmsg_if_net(s);

			continue;
		}

		flagerr = greeting();
		if (flagerr < 0) {
			quitmsg_if_net(flagerr);
			continue;
		}

		smtpext = flagerr;

		if (smtpext & esmtp_starttls) {
			flagerr = tls_init(d, tlsa);
			/* Local error, this would likely happen on the next host again.
			 * Since it's a local fault stop trying and hope it gets fixed. */
			if (flagerr < 0) {
				daneinfo_free(d, tlsa);
				net_conn_shutdown(shutdown_clean);
			}

			if (flagerr != 0) {
				quitmsg_if_net(-flagerr);
				continue;
			}

			flagerr = greeting();

			if (flagerr < 0) {
				quitmsg_if_net(flagerr);
				continue;
			} else {
				smtpext = flagerr;
			}
		} else if (clientcertbuf != NULL) {
			const char *dropmsg[] = { "no STARTTLS offered by ", rhost, ", but TLS certificate is configured", NULL };

			log_writen(LOG_WARNING, dropmsg);

			quitmsg();
			continue;
		} else if (tlsa > 0) {
			const char *dropmsg[] = { "no STARTTLS offered by ", rhost, ", but TLSA record exists", NULL };

			log_writen(LOG_WARNING, dropmsg);

			quitmsg();
			continue;
		}
	} while (socketd < 0);

	daneinfo_free(d, tlsa);

	return 0;
}
