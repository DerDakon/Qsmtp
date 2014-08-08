#include <netinet/in.h>
#include <syslog.h>
#include <qsmtpd/userfilters.h>

#include <qsmtpd/antispam.h>
#include "control.h"
#include "log.h"
#include "netio.h"
#include "match.h"
#include <qsmtpd/qsmtpd.h>

#include <assert.h>
#include <arpa/inet.h>

static struct {
	struct in_addr net;
	const unsigned char len;
} reserved_netsv4[] = {
	{
		/* private net a, 10/8 */
		.len = 8
	},
	{
		/* private net b, 172.16/12 */
		.len = 12
	},
	{
		/* private net c, 192.168/16 */
		.len = 16
	},
	{
		/* link local, 169.254/16 */
		.len = 16
	},
	{
		/* TEST-NET-1, 192.0.2/24 */
		.len = 24
	},
	{
		/* TEST-NET-2, 198.51.100/24 */
		.len = 24
	},
	{
		/* TEST-NET-3, 203.0.113/24 */
		.len = 24
	},
	{
		/* benchmarking, 192.18/15 */
		.len = 15
	}
};

static struct {
	struct in6_addr net;
	const unsigned char len;
} reserved_netsv6[] = {
	{
		/* ORCHID, 2001:10/28 */
		.len = 28
	},
	{
		/* Documentation, 2001:db8/32 */
		.len = 32
	}
};

static void
init_nets(void)
{
	/* private net a */
	reserved_netsv4[0].net.s_addr = htonl(0x0a000000);
	/* private net b */
	reserved_netsv4[1].net.s_addr = htonl(0xac100000);
	/* private net c */
	reserved_netsv4[2].net.s_addr = htonl(0xc0a80000);
	/* link local */
	reserved_netsv4[3].net.s_addr = htonl(0xa9fe0000);
	/* TEST-NET-1 */
	reserved_netsv4[4].net.s_addr = htonl(0xc0000200);
	/* TEST-NET-2 */
	reserved_netsv4[5].net.s_addr = htonl(0xc6336400);
	/* TEST-NET-3 */
	reserved_netsv4[6].net.s_addr = htonl(0xcb007100);
	/* benchmarking */
	reserved_netsv4[7].net.s_addr = htonl(0xc0120000);

	/* ORCHID */
	inet_pton(AF_INET6, "2001:10::", &reserved_netsv6[0].net);
	/* Documentation */
	inet_pton(AF_INET6, "2001:db8::", &reserved_netsv6[1].net);
}

/*
 * contents of fromdomain (binary or'ed)
 *
 * 1: reject mail if from domain does not exist
 * 2: reject mail if from domain resolves only to localhost addresses
 * 4: reject mail if from domain resolves only to private nets (RfC 1918)
 */
enum filter_result
cb_fromdomain(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	long u;			/* contents of control setting is stored here */

	/* we can't check the from domain on a bounce message */
	if (!xmitstat.mailfrom.len)
		return FILTER_PASSED;

	/* if there is a syntax error in the file it's the users fault and this mail will be accepted */
	if ( (u = getsettingglobal(ds, "fromdomain", t)) <= 0)
		return FILTER_PASSED;

	if (u & 1) {
/* check if domain exists in DNS */
		if (!xmitstat.frommx) {
			const char *errmsg;

			switch (xmitstat.fromdomain) {
			case DNS_ERROR_TEMP:
				*logmsg = "temporary DNS error on from domain lookup";
				errmsg = "451 4.4.3 temporary DNS failure\r\n";
				break;
			case DNS_ERROR_PERM:
				*logmsg = "NXDOMAIN";
				errmsg = "501 5.1.8 Domain of sender address does not exist\r\n";
				break;
			case 1:
				*logmsg = "no MX";
				errmsg = "501 5.1.8 Sorry, can't find a mail exchanger for sender address\r\n";
				break;
			default:
				assert(xmitstat.fromdomain == 1);
				return FILTER_PASSED;
			}

			return netwrite(errmsg) ? FILTER_ERROR : FILTER_DENIED_WITH_MESSAGE;
		}
	}
	if ((u & 6) && (xmitstat.frommx != NULL)) {
		/* check if all MX entries resolve to private networks or are loopbacks */
		int flaghit = 1;
		struct ips *thisip;
		unsigned short s;

		if (reserved_netsv4[0].net.s_addr == 0)
			init_nets();

		FOREACH_STRUCT_IPS(thisip, s, xmitstat.frommx) {
			if (IN6_IS_ADDR_V4MAPPED(thisip->addr + s)) {
				int flagtmp = 0;
				unsigned int i;

				if (u & 4)
					for (i = 0; i < sizeof(reserved_netsv4) / sizeof(reserved_netsv4[0]); i++)
						if (ip4_matchnet(thisip->addr + s, &reserved_netsv4[i].net, reserved_netsv4[i].len)) {
							flagtmp = 1;
							break;
						}

				if ((u & 2) && !flagtmp) {
					unsigned int net = (thisip->addr[s].s6_addr32[3] & htonl(0xff000000));

					/* block if net is in 0/8 or 127/8 */
					if ((net == 0) || (net == htonl(0x7f000000)))
						flagtmp = 1;
				}

				flaghit &= flagtmp;
			} else {
				int flagtmp = 0;
				unsigned int i;

				if (u & 4) {
					for (i = 0; i < sizeof(reserved_netsv6) / sizeof(reserved_netsv6[0]); i++) {
						if (ip6_matchnet(thisip->addr + s, &reserved_netsv6[i].net, reserved_netsv6[i].len)) {
							flagtmp = 1;
							break;
						}
					}

					if (!flagtmp)
						flagtmp = IN6_IS_ADDR_LINKLOCAL(thisip->addr + s) || IN6_IS_ADDR_SITELOCAL(thisip->addr + s);
				}

				if ((u & 2) && !flagtmp) {
					if (IN6_IS_ADDR_LOOPBACK(thisip->addr + s))
						flagtmp = 1;
				}

				flaghit &= flagtmp;
			}
			if (!flaghit)
				break;
		}
		if (flaghit) {
			*logmsg = "unroutable MX";
			return netwrite("501 5.4.0 none of your mail exchangers has a routable address\r\n") ?
					FILTER_ERROR : FILTER_DENIED_WITH_MESSAGE;
		}
	}
#ifdef IPV4ONLY
	/* check if all MX entries point to IPv6 addresses */
	if (u) {
		int flaghit;
		struct ips *thisip;
		unsigned short s;

		if ( (flaghit = getsettingglobal(ds, "reject_ipv6only", t)) <= 0)
			return FILTER_PASSED;

		FOREACH_STRUCT_IPS(thisip, s, xmitstat.frommx) {
			if (IN6_IS_ADDR_V4MAPPED(thisip->addr + s)) {
				flaghit = 0;
				break;
			}
		}
		if (flaghit) {
			*logmsg = "IPv6 only";
			return netwrite("501 5.4.0 all your mail exchangers have IPv6 addresses and I am an IPv4-only host\r\n") ?
					FILTER_ERROR : FILTER_DENIED_WITH_MESSAGE;
		}
	}
#endif
	return FILTER_PASSED;
}
