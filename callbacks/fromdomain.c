#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include "antispam.h"
#include "usercallback.h"
#include "control.h"
#include "dns.h"
#include "log.h"
#include "netio.h"
#include "qsmtpd.h"

char *logmess[] = {"no MX", "temporary DNS error on from domain lookup", "NXDOMAIN"};

/*
 * contents of fromdomain (binary or'ed)
 *
 * 1: reject mail if from domain does not exist
 * 2: reject mail if from domain resolves only to localhost addresses
 * 3: reject mail if from domain resolves only to private nets (RfC 1918)
 */
int
cb_fromdomain(const struct userconf *ds, char **logmsg, int *t)
{
	long u;			/* contents of control setting is stored here */

	/* we can't check the from domain on a bounce message */
	if (!xmitstat.mailfrom.len)
		return 0;

	/* if there is a syntax error in the file it's the users fault and this mail will be accepted */
	if ( (u = getsettingglobal(ds, "fromdomain", t)) <= 0)
		return 0;

	if (u & 1) {
/* check if domain exists in DNS */
		if (!xmitstat.frommx) {
			const char *errmsg[] = {"501 5.1.8 Sorry, can't find a mail exchanger for sender address\r\n",
						"451 4.4.3 temporary DNS failure\r\n",
						"501 5.1.8 Domain of sender address does not exist\r\n"};

			*logmsg = logmess[xmitstat.fromdomain - 1];
			return netwrite(errmsg[xmitstat.fromdomain - 1]) ? -1 : 1;
		}
	}
	if (u & 2) {
/* check if all MX entries are loopbacks */
		int flaghit = 1;
		struct ips *thisip;

		while (flaghit && (thisip = xmitstat.frommx)) {
			if (IN6_IS_ADDR_V4MAPPED(&(thisip->addr))) {
				if ((thisip->addr.s6_addr32[3] & htonl(0xff000000)) != htonl(0x7f000000))
					flaghit = 0;
			} else {
				if (!IN6_IS_ADDR_LOOPBACK(&(thisip->addr)))
					flaghit = 0;
			}
		}
		if (flaghit) {
			*logmsg = "DNS loop";
			return netwrite("501 5.4.0 all your mail exchangers have loopback addresses\r\n") ? -1 : 1;
		}
	}
	if (u & 4) {
/* check if all MX entries resolve to private networks */
		int flaghit = 1;
		struct ips *thisip;

		while (flaghit && (thisip = xmitstat.frommx)) {
			if (IN6_IS_ADDR_V4MAPPED(&(thisip->addr))) {
				int flagtmp = 0;
				/* 10.0.0.0/8 */
				if ((thisip->addr.s6_addr32[3] & htonl(0xff000000)) == htonl(0x0a000000))
					flagtmp = 1;
				/* 172.16.0.0/12 */
				if (!flagtmp && ((thisip->addr.s6_addr32[3] & htonl(0xfff00000)) == htonl(0xac100000)))
					flagtmp = 1;
				/* 192.168.0.0/16 */
				if (!flagtmp && ((thisip->addr.s6_addr32[3] & htonl(0xffff0000)) == htonl(0xc0a80000)))
					flagtmp = 1;
				if (!flagtmp)
					flaghit = 0;
			} else {
				flaghit = IN6_IS_ADDR_LINKLOCAL(&(thisip->addr)) || IN6_IS_ADDR_SITELOCAL(&(thisip->addr));
			}
		}
		if (flaghit) {
			*logmsg = "MX in private network";
			return netwrite("501 5.4.0 all your mail exchangers point to local networks\r\n") ? -1 : 1;
		}
	}
#ifdef IPV4ONLY
	/* check if all MX entries point to IPv6 addresses */
	if (u) {
		int flaghit = 0;
		struct ips *thisip;
		int fd;

		fd = open("control/ipv4only", O_RDONLY);
		if (fd) {
			close(fd);
			flaghit = 1;
		} else {
			/* ignore all other errors here, this only means for us we don't care about this check for now */
			if (errno == ENOMEM)
				return -1;
		}
		while (flaghit && (thisip = xmitstat.frommx)) {
			if (IN6_IS_ADDR_V4MAPPED(&(thisip->addr)))
				flaghit = 0;
		}
		if (flaghit) {
			*logmsg = "IPv6 only";
			return netwrite("501 5.4.0 all your mail exchangers have IPv6 addresses and I am a IPv4-only host\r\n") ? -1 : 1;
		}
	}
#endif
	return 0;
}
