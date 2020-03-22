#include <qsmtpd/userfilters.h>

#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>
#include "test_io/testcase_io.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct xmitstat xmitstat;
unsigned int goodrcpt;
struct recip *thisrecip;
const char **globalconf;

extern int cb_fromdomain(const struct userconf *ds, const char **logmsg, enum config_domain *t);

static int err;

static struct userconf ds;

/**
 * @brief check result of cb_fromdomain()
 * @param r_expect expected return value
 * @param name name of the test
 * @param elog expected log pattern
 */
static int
check_expect(const int r_expect, const char *name, const char *elog)
{
	enum config_domain t = -1;
	const char *logmsg = NULL;

	/* seriously: one can't have a log pattern if the filter passes */
	assert((r_expect == 0) == (elog == NULL));

	fprintf(stderr, "Test: %s\n", name);
	int r = cb_fromdomain(&ds, &logmsg, &t);

	if (logmsg == NULL) {
		if (elog != NULL) {
			fprintf(stderr, "cb_fromdomain() should have set log pattern %s but returned NULL\n",
					elog);
			err++;
		}
	} else if (strcmp(elog, logmsg) != 0) {
		fprintf(stderr, "cb_fromdomain() should have set log pattern %s but returned %s\n",
				elog, logmsg);
		err++;
	}

	if (r == r_expect)
		return 0;

	fprintf(stderr, "cb_fromdomain() should have returned %i but returned %i, message '%s', t %i\n",
			r_expect, r, logmsg, t);

	return 1;
}

/* set up this IP as sender and MX ip */
static void
setup_ip(const char *ip)
{
	assert(strlen(ip) < sizeof(xmitstat.remoteip));
	strcpy(xmitstat.remoteip, ip);
	int r = inet_pton(AF_INET6, xmitstat.remoteip, &xmitstat.sremoteip);
	assert(r == 1);

	xmitstat.ipv4conn = IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip);

	if (xmitstat.frommx == NULL)
		return;

	xmitstat.fromdomain = 0;
	*xmitstat.frommx->addr = xmitstat.sremoteip;
}

static struct testaddrs {
	const char *name;
	unsigned int bit;
} ipstrs[] = {
	{
		.name = "::ffff:127.0.0.1",
		.bit = 1
	},
	{
		.name = "::ffff:127.1.1.2",
		.bit = 1
	},
	{
		.name = "::ffff:172.16.15.14",
		.bit = 2
	},
	{
		.name = "::ffff:10.9.8.7",
		.bit = 2
	},
	{
		.name = "::ffff:192.168.167.166",
		.bit = 2
	},
	{
		.name = "::1",
		.bit = 1
	},
	{
		.name = "::",
		.bit = 1
	},
	{
		.name = "fe80::2:3:44",
		.bit = 2
	},
	{
		.name = "::ffff:8.8.8.8",	// valid entry for checking in main()
	}
};
static char configline[32];

/**
 * @brief check if all invalid addresses are rejected
 */
static int
check_reject(void)
{
	struct in6_addr ip;
	int ret = 0;
	struct ips mx = {
		.addr = &ip,
		.count = 1
	};

	/* ignore the valid entry at the end */
	for (unsigned int i = 0; i < sizeof(ipstrs) / sizeof(ipstrs[0]) - 1; i++) {
		int r = inet_pton(AF_INET6, ipstrs[i].name, &ip);
		assert(r == 1);
		char testname[64];

		snprintf(configline, sizeof(configline), "fromdomain=%u", 1 << ipstrs[i].bit);
		xmitstat.frommx = &mx;
		snprintf(testname, sizeof(testname), "invalid IP test %i", i + 1);
		netnwrite_msg = "501 5.4.0 none of your mail exchangers has a routable address\r\n";
		ret += check_expect(1, testname, "unroutable MX");
	}

	return ret;
}

int
main(void)
{
	char *configarray[] = {
		configline,
		NULL
	};
	struct in6_addr frommxip;
	struct ips frommx = {
		.addr = &frommxip,
		.priority = 42,
		.count = 1
	};
	struct ips frommx_mixed_invalid[3] = {
		{
			.priority = 0,
			.count = 1
		},
		{
			.priority = 1,
			.count = 1
		},
		{
			.priority = 2,
			.count = 1
		}
	};
	struct ips frommx_mixed[3] = {
		{
			.priority = 0,
			.count = 3
		},
		{
			.priority = 2,
			.count = 1
		},
		{
			.priority = 3,
			.count = 5
		}
	};
	struct in6_addr frommx_mixed_addr[frommx_mixed[0].count + frommx_mixed[1].count + frommx_mixed[2].count];

	frommx_mixed_invalid[0].next = frommx_mixed_invalid + 1;
	frommx_mixed_invalid[1].next = frommx_mixed_invalid + 2;

	/* set up a list of many invalid IPs and the last one is ok */
	for (unsigned int i = 0; i < sizeof(frommx_mixed_addr) / sizeof(frommx_mixed_addr[0]); i++) {
		int r = inet_pton(AF_INET6, ipstrs[i].name, frommx_mixed_addr + i);
		assert(r == 1);
	}

	/* set up a list of multiple invalid IPs */
	for (unsigned int i = 0; i < sizeof(frommx_mixed_invalid) / sizeof(frommx_mixed_invalid[0]); i++)
		frommx_mixed_invalid[i].addr = frommx_mixed_addr + i;

	frommx_mixed[0].next = frommx_mixed + 1;
	frommx_mixed[0].addr = frommx_mixed_addr;
	frommx_mixed[1].next = frommx_mixed + 2;
	frommx_mixed[1].addr = frommx_mixed[0].addr + frommx_mixed[0].count;
	frommx_mixed[2].addr = frommx_mixed[1].addr + frommx_mixed[1].count;

	testcase_setup_netnwrite(testcase_netnwrite_compare);

	memset(&ds, 0, sizeof(ds));
	globalconf = NULL;

	ds.userconf = configarray;
	sprintf(configline, "fromdomain=0");

	err += check_expect(0, "checking empty fromdomain", NULL);

	xmitstat.mailfrom.s = "foo@example.org";
	xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);

	err += check_expect(0, "checking deactivated fromdomain filter", NULL);

	sprintf(configline, "fromdomain=6");
	setup_ip("::ffff:172.16.42.42");

	err += check_expect(0, "checking local net 172.16.42.42 without MX", NULL);

	xmitstat.frommx = &frommx;
	setup_ip("::ffff:172.16.42.42");
	netnwrite_msg = "501 5.4.0 none of your mail exchangers has a routable address\r\n";
	err += check_expect(1, "checking local net 172.16.42.42", "unroutable MX");

	/* TEST-NET-1 */
	setup_ip("::ffff:192.0.2.1");
	netnwrite_msg = "501 5.4.0 none of your mail exchangers has a routable address\r\n";
	err += check_expect(1, "checking TEST-NET-1 192.0.2.1", "unroutable MX");

	/* TEST-NET-2 */
	setup_ip("::ffff:198.51.100.2");
	netnwrite_msg = "501 5.4.0 none of your mail exchangers has a routable address\r\n";
	err += check_expect(1, "checking TEST-NET-2 198.51.100.2", "unroutable MX");

	/* TEST-NET-3 */
	setup_ip("::ffff:203.0.113.3");
	netnwrite_msg = "501 5.4.0 none of your mail exchangers has a routable address\r\n";
	err += check_expect(1, "checking TEST-NET-3 203.0.113.3", "unroutable MX");

	/* ORCHID */
	setup_ip("2001:10::17:14");
	netnwrite_msg = "501 5.4.0 none of your mail exchangers has a routable address\r\n";
	err += check_expect(1, "checking ORCHID 2001:10::17:14", "unroutable MX");

	/* Documentation */
	setup_ip("2001:db8::1822:13:0:1");
	netnwrite_msg = "501 5.4.0 none of your mail exchangers has a routable address\r\n";
	err += check_expect(1, "checking documentation net 2001:db8::1822:13:0:1", "unroutable MX");

	sprintf(configline, "fromdomain=1");

	xmitstat.fromdomain = 1;
	xmitstat.frommx = NULL;
	netnwrite_msg = "501 5.1.8 Sorry, can't find a mail exchanger for sender address\r\n";
	err += check_expect(1, "checking no MX", "no MX");

	xmitstat.fromdomain = 2;
	xmitstat.frommx = NULL;
	netnwrite_msg = "501 5.1.8 Sorry, the sender domain does not accept mails\r\n";
	err += check_expect(1, "checking null MX", "null MX");

	xmitstat.fromdomain = DNS_ERROR_TEMP;
	xmitstat.frommx = NULL;
	netnwrite_msg = "451 4.4.3 temporary DNS failure\r\n";
	err += check_expect(1, "checking MX temp error", "temporary DNS error on from domain lookup");

	xmitstat.fromdomain = DNS_ERROR_PERM;
	xmitstat.frommx = NULL;
	netnwrite_msg = "501 5.1.8 Domain of sender address does not exist\r\n";
	err += check_expect(1, "checking MX perm error", "NXDOMAIN");

	sprintf(configline, "fromdomain=7");
	xmitstat.frommx = &frommx;
	setup_ip("::ffff:8.8.8.8");
	err += check_expect(0, "checking Google public DNS", NULL);

	setup_ip("::ffff:8.8.8.8");
	xmitstat.frommx = frommx_mixed_invalid;
	netnwrite_msg = "501 5.4.0 none of your mail exchangers has a routable address\r\n";
	err += check_expect(1, "checking multiple invalid addresses", "unroutable MX");

	xmitstat.frommx = frommx_mixed;
	err += check_expect(0, "checking mixed invalid addresses ending in Google public DNS", NULL);

	sprintf(configline, "fromdomain=2");
	xmitstat.frommx = &frommx;
	setup_ip("::ffff:127.4.5.6");
	netnwrite_msg = "501 5.4.0 none of your mail exchangers has a routable address\r\n";
	err += check_expect(1, "checking IPv4 loopback net", "unroutable MX");

	sprintf(configline, "fromdomain=2");
	setup_ip("::1");
	netnwrite_msg = "501 5.4.0 none of your mail exchangers has a routable address\r\n";
	err += check_expect(1, "checking IPv6 loopback net", "unroutable MX");

	setup_ip("feab::42:42:42");
	netnwrite_msg = "501 5.4.0 none of your mail exchangers has a routable address\r\n";
	err += check_expect(0, "checking IPv6 link local net when only loopback is forbidden", NULL);

	sprintf(configline, "fromdomain=4");
	netnwrite_msg = "501 5.4.0 none of your mail exchangers has a routable address\r\n";
	err += check_expect(1, "checking IPv6 link local net", "unroutable MX");

	if (netnwrite_msg != NULL)
		err++;

	sprintf(configline, "fromdomain=7");
	err += check_reject();

	return err;
}
