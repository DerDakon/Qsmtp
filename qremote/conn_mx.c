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

#include <errno.h>
#include <syslog.h>
#include <unistd.h>

void
connect_mx(struct ips *mx, const struct in6_addr *outip4, const struct in6_addr *outip6)
{
	/* for all MX entries we got: try to enable connection, check if the SMTP server wants us
	 * (sends 220 response) and EHLO/HELO succeeds. If not, try next. If none left, exit. */
	do {
		int flagerr = 0;
		int s;

		if (socketd >= 0)
			close(socketd);
		socketd = tryconn(mx, outip4, outip6);
		dup2(socketd, 0);
		getrhost(mx);

		s = netget();

		/* consume the rest of the replies */
		while (linein.s[3] == '-') {
			if (net_read() == 0)
				continue;

			flagerr = 1;
			switch (errno) {
			case ENOMEM:
				err_mem(1);
			case EINVAL:
			case E2BIG:
				write_status("Z5.5.2 syntax error in server reply");
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
		if (s != 220) {
			quitmsg();
			continue;
		}
		if (flagerr)
			continue;

		if (strncmp("220 ", linein.s, 4) != 0) {
			const char *dropmsg[] = {"invalid greeting from ", rhost, NULL};

			log_writen(LOG_WARNING, dropmsg);
			quitmsg();
		} else {
			flagerr = greeting();
			if (flagerr < 0)
				quitmsg();
			else
				smtpext = flagerr;
		}
	} while (socketd < 0);
}
