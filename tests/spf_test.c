/** \file spf_test.c
 \brief SPF testcases
 */
#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "qsmtpd.h"
#include "antispam.h"
#include "sstring.h"

enum dnstype {
	DNSTYPE_A,
	DNSTYPE_AAAA,
	DNSTYPE_MX,
	DNSTYPE_NAME,
	DNSTYPE_TXT,
	DNSTYPE_NONE /* end marker */
};

struct dnsentry {
	enum dnstype type;
	const char *key;
	const char *value;
};

const struct dnsentry *dnsdata;

static const char *
dnsentry_search(const enum dnstype stype, const char *skey)
{
	unsigned int i = 0;

	while (dnsdata[i].type != DNSTYPE_NONE) {
		if (dnsdata[i].type != stype) {
			i++;
			continue;
		}

		if (strcmp(dnsdata[i].key, skey) != 0) {
			i++;
			continue;
		}

		return dnsdata[i].value;
	}

	return NULL;
}

struct ips *
parseips(const char *list)
{
	const char *next = list;
	struct ips *ret = NULL;

	while (next != NULL) {
		char this[INET6_ADDRSTRLEN];
		char *end = strchr(next, ';');
		struct ips *n = malloc(sizeof(*n));

		if (n == NULL)
			exit(ENOMEM);

		if (end == NULL) {
			strcpy(this, next);
		} else {
			strncpy(this, next, end - next);
		}

		memset(n, 0, sizeof(*n));
		inet_pton(AF_INET6, this, &n->addr);
		n->priority = 42;
		n->next = ret;
		ret = n;

		next = end;
	}

	return ret;
}

int
ask_dnsmx(const char *domain, struct ips **ips)
{
	const char *value = dnsentry_search(DNSTYPE_MX, domain);

	if (value == NULL)
		return 1;

	*ips = parseips(value);

	return 0;
}

int
ask_dnsaaaa(const char *domain, struct ips **ips)
{
	const char *value = dnsentry_search(DNSTYPE_AAAA, domain);

	if (value == NULL)
		return 1;

	*ips = parseips(value);

	return 0;
}

int
ask_dnsa(const char *domain, struct ips **ips)
{
	const char *value = dnsentry_search(DNSTYPE_A, domain);

	if (value == NULL)
		return 1;

	*ips = parseips(value);

	return 0;
}

int
ask_dnsname(const struct in6_addr *addr, char **name)
{
	char iptmp[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, iptmp, sizeof(iptmp));

	const char *value = dnsentry_search(DNSTYPE_NAME, iptmp);

	if (value == NULL)
		return 1;

	*name = malloc(strlen(value)) + 1;
	if (*name == NULL)
		return -1;

	strcpy(*name, value);

	return 0;
}

int
dnstxt(char **out, const char *host)
{
	const char *value = dnsentry_search(DNSTYPE_TXT, host);

	if (value == NULL) {
		errno = ENOENT;
		return -1;
	}

	*out = malloc(strlen(value) + 1);
	if (*out == NULL)
		return -1;

	strcpy(*out, value);

	return 0;
}

struct spftestcase {
	const char *helo;
	const char *from;
	const char *goodip;
	const char *badip;
	struct dnsentry dns[];
};

struct spftestcase spftest_redhat = {
	.helo = "mx1.redhat.com",
	.from = "foobar@redhat.com",
	.goodip = "::ffff:209.132.183.28",
	.badip = "::ffff:10.0.1.5",
	.dns = {
		{
			.type = DNSTYPE_A,
			.key = "mailer.market2lead.com",
			.value = "64.13.137.15"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "redhat.com",
			.value = "v=spf1 include:spf-2.redhat.com include:spf-1.redhat.com -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "spf-1.redhat.com",
			.value = "v=spf1 ip4:204.16.104.38 ip4:66.187.233.31 ip4:66.187.237.31 ip4:66.187.233.32 ip4:66.187.233.33 ip4:209.132.183.24 ip4:209.132.183.25 ip4:209.132.183.26 ip4:209.132.183.27 ip4:209.132.183.28 a:mailer.market2lead.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "spf-2.redhat.com",
			.value = "v=spf1 mx ip4:204.14.234.13 ip4:204.14.232.13 ip4:204.14.234.14 ip4:204.14.232.14 ip4:209.132.177.0/24 ip4:65.125.54.185 ip4:65.125.54.186 ip4:65.125.54.187 ip4:65.125.54.188 ip4:65.125.54.189 ip4:65.125.54.190 ip4:219.120.63.242"
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		}
	}
};

struct spftestcase spftest_sfmail = {
	.helo = "mail.sf-mail.de",
	.from = "eike@sf-mail.de",
	.goodip = "::ffff:62.27.20.61",
	.badip = "::ffff:62.27.20.62",
	.dns = {
		{
			.type = DNSTYPE_MX,
			.key = "sf-mail.de",
			.value = "::ffff:62.27.20.61"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "sf-mail.de",
			.value = "v=spf1 mx -all"
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		}
	}
};

struct xmitstat xmitstat;
string heloname;

int runtest(struct spftestcase *tc)
{
	memset(&xmitstat, 0, sizeof(xmitstat));

	if (newstr(&xmitstat.mailfrom, strlen(tc->from)))
		return ENOMEM;

	if (newstr(&heloname, strlen(tc->helo)))
		return ENOMEM;

	dnsdata = tc->dns;

	strncpy(xmitstat.remoteip, tc->goodip, sizeof(xmitstat.remoteip));
	inet_pton(AF_INET6, tc->goodip, &xmitstat.sremoteip);

	int r = check_host(strchr(tc->from, '@') + 1);
	if (SPF_FAIL(r)) {
		puts("good IP did not pass");
		return -1;
	}

	if (tc->badip == NULL)
		return 0;

	strncpy(xmitstat.remoteip, tc->badip, sizeof(xmitstat.remoteip));
	inet_pton(AF_INET6, tc->badip, &xmitstat.sremoteip);

	r = check_host(strchr(tc->from, '@') + 1);
	if (!SPF_FAIL(r)) {
		puts("bad IP passed");
		return -2;
	}

	free(xmitstat.mailfrom.s);
	STREMPTY(xmitstat.mailfrom);
	free(heloname.s);
	STREMPTY(heloname);

	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 1)
		return EINVAL;

	if (strcmp(argv[1], "redhat") == 0)
		return runtest(&spftest_redhat);
	else if (strcmp(argv[1], "sf-mail") == 0)
		return runtest(&spftest_sfmail);
	else
		return EINVAL;
}

void log_writen(int priority __attribute__ ((unused)), const char **msg __attribute__ ((unused)))
{
}

inline void log_write(int priority __attribute__ ((unused)), const char *msg __attribute__ ((unused)))
{
}

int data_pending(void)
{
	return 1;
}

#include "tls.h"
SSL *ssl;
