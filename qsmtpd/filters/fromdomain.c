#include <netinet/in.h>
#include <syslog.h>
#include "antispam.h"
#include "userfilters.h"
#include "control.h"
#include "log.h"
#include "netio.h"
#include "qsmtpd.h"
#include "match.h"

char *logmess[] = {"no MX", "temporary DNS error on from domain lookup", "NXDOMAIN"};

/*
 * contents of fromdomain (binary or'ed)
 *
 * 1: reject mail if from domain does not exist
 * 2: reject mail if from domain resolves only to localhost addresses
 * 4: reject mail if from domain resolves only to private nets (RfC 1918)
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
		struct ips *thisip = xmitstat.frommx;

		while (flaghit && thisip) {
			if (IN6_IS_ADDR_V4MAPPED(&(thisip->addr))) {
				unsigned int net = (thisip->addr.s6_addr32[3] & htonl(0xff000000));

				/* block if net is in 0/8 or 127/8 */
					if (net && (net != htonl(0x7f000000)))
					flaghit = 0;
			} else {
				if (!IN6_IS_ADDR_LOOPBACK(&(thisip->addr)))
					flaghit = 0;
			}
			thisip = thisip->next;
		}
		if (flaghit) {
			*logmsg = "DNS loop";
			return netwrite("501 5.4.0 all your mail exchangers have loopback addresses\r\n") ? -1 : 1;
		}
	}
	if (u & 4) {
/* check if all MX entries resolve to private networks */
		int flaghit = 1;
		struct ips *thisip = xmitstat.frommx;

		while (flaghit && thisip) {
			if (IN6_IS_ADDR_V4MAPPED(&(thisip->addr))) {
				int flagtmp = 0;
				const struct in_addr priva =   { .s_addr = htonl(0x0a000000) }; /* 10/8 */
				const struct in_addr privb =   { .s_addr = htonl(0xac100000) }; /* 172.16/12 */
				const struct in_addr privc =   { .s_addr = htonl(0xc0a80000) }; /* 192.168/16 */
				const struct in_addr linkloc = { .s_addr = htonl(0xa9fe0000) }; /* 169.254/16 */
				const struct in_addr testnet = { .s_addr = htonl(0xc0000200) }; /* 192.0.2/24 */
				const struct in_addr bench =   { .s_addr = htonl(0xc0120000) }; /* 192.18/15 */

				/* 10.0.0.0/8 */
				if (ip4_matchnet(&(thisip->addr), &priva, 8))
					flagtmp = 1;
				/* 172.16.0.0/12 */
				if (!flagtmp && ip4_matchnet(&(thisip->addr), &privb, 12))
					flagtmp = 1;
				/* 192.168.0.0/16 */
				if (!flagtmp && ip4_matchnet(&(thisip->addr), &privc, 16))
					flagtmp = 1;
				/* 169.254.0.0/16 */
				if (!flagtmp && ip4_matchnet(&(thisip->addr), &linkloc, 16))
					flagtmp = 1;
				/* 192.0.2.0/24 */
				if (!flagtmp && ip4_matchnet(&(thisip->addr), &testnet, 24))
					flagtmp = 1;
				/* 192.0.2.0/24 */
				if (!flagtmp && ip4_matchnet(&(thisip->addr), &bench, 15))
					flagtmp = 1;
				if (!flagtmp)
					flaghit = 0;
			} else {
				flaghit = IN6_IS_ADDR_LINKLOCAL(&(thisip->addr)) || IN6_IS_ADDR_SITELOCAL(&(thisip->addr));
			}
			thisip = thisip->next;
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

		if ( (flaghit = getsettingglobal(ds, "reject_ipv6only", t)) <= 0)
			return 0;

		for (thisip = xmitstat.frommx; flaghit && thisip; thisip = thisip->next) {
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
