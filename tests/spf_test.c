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
#include <unistd.h>
#include <mime.h>

enum dnstype {
	DNSTYPE_A,
	DNSTYPE_AAAA,
	DNSTYPE_MX,
	DNSTYPE_NAME,
	DNSTYPE_TXT,
	DNSTYPE_SPF,
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

	if (dnsdata == NULL)
		return NULL;

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

static struct ips *
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
			this[end - next] = '\0';
			end++;
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

	*ips = NULL;
	if (value == NULL) {
		int r = ask_dnsa(domain, ips);
		struct ips *ip6addr = NULL;
		int q = ask_dnsaaaa(domain, &ip6addr);
		struct ips *cur;

		cur = *ips;
		while (cur != NULL) {
			cur->priority = 65536;
			cur = cur->next;
		}
		cur = ip6addr;
		while (cur != NULL) {
			cur->priority = 65536;
			cur = cur->next;
		}

		if (q != 0) {
			return r;
		} else if (q == 0) {
			cur = ip6addr;
			while (cur->next != NULL)
				cur = cur->next;
			cur->next = *ips;
			*ips = cur;
			return 0;
		} else {
			*ips = ip6addr;
			return q;
		}
	}

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

	if (ips != NULL)
		*ips = parseips(value);

	return 0;
}

int
ask_dnsname(const struct in6_addr *addr, char **name)
{
	char iptmp[INET6_ADDRSTRLEN];
	size_t l;
	int cnt = 0;

	inet_ntop(AF_INET6, addr, iptmp, sizeof(iptmp));

	const char *value = dnsentry_search(DNSTYPE_NAME, iptmp);

	if (value == NULL)
		return 0;

	l = strlen(value);
	*name = malloc(l + 2);
	if (*name == NULL)
		return -1;

	strcpy(*name, value);
	(*name)[l + 1] = '\0';
	while (l > 0) {
		if ((*name)[l] == ';') {
			(*name)[l] = '\0';
			cnt++;
		}
		l--;
	}

	return ++cnt;
}

int
dns_resolve_txt(char **out, const char *host, const enum dnstype stype)
{
	const char *value = dnsentry_search(stype, host);

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


int
dnstxt(char **out, const char *host)
{
	int r = dns_resolve_txt(out, host, DNSTYPE_TXT);

	// only for the moment until the SPF library does this calls itself
	if (r == -1 && errno == ENOENT)
		r = dns_resolve_txt(out, host, DNSTYPE_SPF);

	return r;
}

int
dnsspf(char **out, const char *host)
{
	return dns_resolve_txt(out, host, DNSTYPE_SPF);
}

struct spftestcase {
	const char *helo;
	const char *from;
	const char *goodip;
	const char *badip;
	struct dnsentry dns[];
};

static struct spftestcase spftest_redhat = {
	.helo = "mx1.redhat.com",
	.from = "foobar@redhat.com",
	.goodip = "::ffff:209.132.183.28",
	.badip = "::ffff:10.0.1.5",
	.dns = {
		{
			.type = DNSTYPE_A,
			.key = "mailer.market2lead.com",
			.value = "::ffff:64.13.137.15"
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

static struct spftestcase spftest_sfmail = {
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

static int
check_received(int spfstatus, int log)
{
	int fd[2];
	char buf[1024];
	int r;
	ssize_t off = 0;
	const char hdrline[] = "Received-SPF: ";
	const char *spfstates[] = { "pass", "fail", "softfail", "none", "neutral", "temperror", "permerror", NULL };
	const char *tmp;

	if (pipe(fd) != 0) {
		fputs("Can not create pipes\n", stderr);
		return 1;
	}

	memset(buf, 0, sizeof(buf));
	r = spfreceived(fd[1], spfstatus);
	close(fd[1]);

	if (r != 0) {
		fprintf(stderr, "spfreceived returned %i\n", r);
		close(fd[0]);
		return 1;
	}

	do {
		ssize_t cnt = read(fd[0], buf + off, sizeof(buf) - 1 - off);
		if (cnt < 0) {
			fprintf(stderr, "error %i when reading from pipe\n", errno);
			close(fd[0]);
			return 1;
		}
		if (cnt == 0)
			break;
		off += cnt;
	} while (off < sizeof(buf) - 1);

	close(fd[0]);
	buf[sizeof(buf) - 1] = '\0';

	if (spfstatus == SPF_IGNORE) {
		if (off != 0) {
			fprintf(stderr, "spfreceived(fd, SPF_IGNORE) should not write to pipe, but has written %zi byte\n", off);
			return 1;
		} else {
			return 0;
		}
	}

	if (strlen(buf) != off) {
		fprintf(stderr, "spfreceived() has written a 0 byte into the input stream at position %zi\n", strlen(buf));
		return 1;
	}

	if (off == 0) {
		fputs("spfreceived() has not written any data\n", stderr);
		return 1;
	}

	if (buf[strlen(buf) - 1] != '\n') {
		fputs("spfreceived() did not terminate the line with LF\n", stderr);
		return 1;
	}

	if (strncasecmp(buf, hdrline, strlen(hdrline)) != 0) {
		fputs("output of spfreceived() did not start with Received-SPF:\n", stderr);
		return 1;
	}

	r = 0;
	while ((spfstates[r] != NULL) && (strncasecmp(buf + strlen(hdrline), spfstates[r], strlen(spfstates[r])) != 0))
		r++;

	if (spfstates[r] == NULL) {
		fputs("spfreceived() wrote an unknown SPF status: ", stderr);
		fputs(buf + strlen(hdrline), stderr);
		return 1;
	}

	tmp = buf + strlen(hdrline) + strlen(spfstates[r]);
	if (!WSPACE(*tmp)) {
		fputs("no whitespace after SPF status\n", stderr);
		return 1;
	}
	tmp++;
	if (spfstatus == SPF_FAIL_MALF) {
		/* skip the invalid token that is logged here */
		while ((*tmp != '\n') && (*tmp != ' ') && (*tmp != '('))
			tmp++;
	}

	if (strstr(buf, "  ") != NULL) {
		fputs("spfreceived() has written duplicate whitespace\n", stderr);
		return 1;
	}

	tmp = skipwhitespace(tmp, strlen(tmp));
	/* there should be nothing behind the comment for anything but SPF_PASS */

	if (tmp == NULL) {
		fputs("syntax error skipping whitespace in received line: ", stderr);
		fputs(buf + strlen(hdrline) + strlen(spfstates[r]), stderr);
		return 1;
	}

	if ((tmp == buf + strlen(buf)) && (spfstatus == SPF_PASS)) {
		fputs("spfreceived() did not wrote keywords behind the comment for SPF_PASS\n", stderr);
		return 1;
	}

	while (tmp != buf + strlen(buf)) {
		const char *spfkey[] = { "client-ip", "envelope-from", "helo",
				"problem", "receiver", "identity", "mechanism", NULL };

		if (strncmp(tmp, "x-", 2) == 0) {
			tmp += 2;
			while ((*tmp != '\n') && (*tmp != '='))
				tmp++;
		} else {
			unsigned int i = 0;

			while (spfkey[i] != NULL) {
				if (strncmp(tmp, spfkey[i], strlen(spfkey[i])) == 0) {
					tmp += strlen(spfkey[i]);
					break;
				}
				i++;
			}

			if (spfkey[i] == NULL) {
				fputs("spfreceived() wrote unknown status code: ", stderr);
				fputs(tmp, stderr);
				return 1;
			}

		}

		if (*tmp != '=') {
			fputs("unexpected character in key: ", stderr);
			fputs(tmp, stderr);
			return 1;
		}

		tmp++;
		if (*tmp == '"') {
			tmp++;
			while (*tmp != '"') {
				if (*tmp == '\n') {
					fputs("unmatched quote in value\n", stderr);
					fputs(buf, stderr);
					return 1;
				}
				tmp++;
			}
			tmp++;
		} else {
			while (*tmp != ';') {
				if (*tmp == '\n') {
					if (*(tmp + 1) == '\0') {
						tmp = NULL;
						break;
					}
					fputs("value did not end before end of line\n", stderr);
					fputs(buf, stderr);
					return 1;
				}
				tmp++;
			}
			tmp++;
		}

		tmp = skipwhitespace(tmp, strlen(tmp));
	}

	if (log)
		fputs(buf, stdout);

	return 0;
}

static void
setup_transfer(const char *helo, const char *from, const char *remoteip)
{
	memset(&xmitstat, 0, sizeof(xmitstat));

	if (newstr(&xmitstat.mailfrom, strlen(from)))
		exit(ENOMEM);

	if (newstr(&xmitstat.helostr, strlen(helo)))
		exit(ENOMEM);

	memcpy(xmitstat.mailfrom.s, from, strlen(from));
	memcpy(xmitstat.helostr.s, helo, strlen(helo));

	strncpy(xmitstat.remoteip, remoteip, sizeof(xmitstat.remoteip));
	inet_pton(AF_INET6, remoteip, &xmitstat.sremoteip);

	if (ask_dnsname(&xmitstat.sremoteip, &xmitstat.remotehost.s) > 0)
		xmitstat.remotehost.len = strlen(xmitstat.remotehost.s);
}

static int
runtest(struct spftestcase *tc)
{
	int err = 0;

	setup_transfer(tc->helo, tc->from, tc->goodip);

	dnsdata = tc->dns;

	int r = check_host(strchr(tc->from, '@') + 1);
	if (SPF_FAIL(r)) {
		fprintf(stderr, "good IP did not pass for %s\n", tc->helo);
		err++;
	}
	err += check_received(r, 0);

	if (tc->badip == NULL)
		return 0;

	strncpy(xmitstat.remoteip, tc->badip, sizeof(xmitstat.remoteip));
	inet_pton(AF_INET6, tc->badip, &xmitstat.sremoteip);

	r = check_host(strchr(tc->from, '@') + 1);
	if (!SPF_FAIL(r)) {
		fprintf(stderr, "bad IP passed for %s\n", tc->helo);
		err++;
	}
	err += check_received(r, 0);

	free(xmitstat.mailfrom.s);
	STREMPTY(xmitstat.mailfrom);
	free(xmitstat.helostr.s);
	STREMPTY(xmitstat.helostr);
	free(xmitstat.remotehost.s);
	STREMPTY(xmitstat.remotehost);

	return err;
}

static int
test_parse_ip4()
{
	struct dnsentry ip4entries[] = {
		{
			.type = DNSTYPE_TXT,
			.key = "ipv4test.example.net",
			.value = NULL
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		}
	};
	const char *ip4invalid[] = {
		"v=spf1 ip4:10.255.255.a4",
		"v=spf1 ip4:fef0::abcd:1",
		"v=spf1 ip4:.1",
		"v=spf1 ip4:10.52.42.1/130",
		"v=spf1 ip4:1/0",
		"v=spf1 ip4:10.42.52.52/0",
		"v=spf1 ip4:10.52.52.42/",
		"v=spf1 ip4:255.255.255.255.255",
		"v=spf1 ip4:300.200.100.0",
		NULL
	};
	const char *ip4valid[] = {
		"v=spf1 ip4:10.42.42.42 -all",
		"v=spf1 ip4:10.42.42.0/24 -all",
		"v=spf1 ip4:10.0.0.0/8 -all",
		NULL
	};
	const char *ip4valid_reject[] = {
		"v=spf1 ip4:10.42.42.43 -all",
		"v=spf1 ip4:10.42.42.0/30 -all",
		"v=spf1 ip4:10.0.0.0/16 -all",
		NULL
	};
	int err = 0;
	unsigned int i = 0;
	int r;

	dnsdata = ip4entries;
	i = 0;

	inet_pton(AF_INET6, "::ffff:10.42.42.42", &xmitstat.sremoteip);

	while (ip4invalid[i] != NULL) {
		ip4entries[0].value = ip4invalid[i];

		r = check_host(ip4entries[0].key);
		if (r != SPF_FAIL_MALF) {
			fprintf(stderr, "check_host() did not reject invalid IPv4 entry '%s' as malformed, but returned %i\n", ip4invalid[i], r);
			err++;
		}

		i++;
	}

	i = 0;

	while (ip4valid[i] != NULL) {
		ip4entries[0].value = ip4valid[i];

		r = check_host(ip4entries[0].key);
		if (r != SPF_PASS) {
			fprintf(stderr, "check_host() did not accept '%s', but returned %i\n", ip4valid[i], r);
			err++;
		}

		i++;
	}

	i = 0;

	while (ip4valid_reject[i] != NULL) {
		ip4entries[0].value = ip4valid_reject[i];

		r = check_host(ip4entries[0].key);
		if (r != SPF_FAIL_PERM) {
			fprintf(stderr, "check_host() did not properly reject '%s', but returned %i\n", ip4valid_reject[i], r);
			err++;
		}

		i++;
	}

	inet_pton(AF_INET6, "fef0::abc:001", &xmitstat.sremoteip);
	ip4entries[0].value = ip4valid[0];

	r = check_host(ip4entries[0].key);
	if (r != SPF_FAIL_PERM) {
		fprintf(stderr, "check_host() should reject '%s' with IPv6 address, but returned %i\n", ip4valid[0], r);
		err++;
	}

	return err;
}

static int
test_parse_ip6()
{
	struct dnsentry ip6entries[] = {
		{
			.type = DNSTYPE_TXT,
			.key = "ipv6test.example.net",
			.value = NULL
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		}
	};
	const char *ip6invalid[] = {
		"v=spf1 ip6:fef0:abg::1",
		"v=spf1 ip6::::1",
		"v=spf1 ip6:",
		"v=spf1 ip6:::1/130",
		"v=spf1 ip6::1/0",
		"v=spf1 ip6:::1/0",
		"v=spf1 ip6:::1/ ip6:::1",
		"v=spf1 ip6:::1/ 20",
		"v=spf1 ip6:::1/3b",
		"v=spf1 ip6:abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd",
		"v=spf1 ip6:10.42.42.42",
		NULL
	};
	const char *ip6valid[] = {
		"v=spf1 ip6:fef0::abc:001 -all",
		"v=spf1 ip6:fef0::abc:0/120 -all",
		"v=spf1 ip6:fef0::0/48 -all",
		NULL
	};
	const char *ip6valid_reject[] = {
		"v=spf1 ip6:fef0::abc:002 -all",
		"v=spf1 ip6:fef0::abc:0100/120 -all",
		"v=spf1 ip6:feff::0/48 -all",
		NULL
	};
	int err = 0;
	unsigned int i = 0;
	int r;

	dnsdata = ip6entries;
	i = 0;

	while (ip6invalid[i] != NULL) {
		ip6entries[0].value = ip6invalid[i];

		r = check_host(ip6entries[0].key);
		if (r != SPF_FAIL_MALF) {
			fprintf(stderr, "check_host() did not reject invalid IPv6 entry '%s' as malformed, but returned %i\n", ip6invalid[i], r);
			err++;
		}

		i++;
	}

	i = 0;

	while (ip6valid[i] != NULL) {
		ip6entries[0].value = ip6valid[i];

		r = check_host(ip6entries[0].key);
		if (r != SPF_PASS) {
			fprintf(stderr, "check_host() did not accept '%s', but returned %i\n", ip6valid[i], r);
			err++;
		}

		i++;
	}

	i = 0;

	while (ip6valid_reject[i] != NULL) {
		ip6entries[0].value = ip6valid_reject[i];

		r = check_host(ip6entries[0].key);
		if (r != SPF_FAIL_PERM) {
			fprintf(stderr, "check_host() did not properly reject '%s', but returned %i\n", ip6valid_reject[i], r);
			err++;
		}

		i++;
	}

	inet_pton(AF_INET6, "::ffff:10.42.42.42", &xmitstat.sremoteip);
	ip6entries[0].value = ip6valid[0];

	r = check_host(ip6entries[0].key);
	if (r != SPF_FAIL_PERM) {
		fprintf(stderr, "check_host() should reject '%s' with IPv4 address, but returned %i\n", ip6valid[0], r);
		err++;
	}

	return err;
}

static int
test_parse_mx()
{
	struct dnsentry mxentries[] = {
		{
			.type = DNSTYPE_TXT,
			.key = "mxtest.example.net",
			.value = NULL
		},
		{
			.type = DNSTYPE_MX,
			.key = "mxtest.example.net",
			.value = "::ffff:10.42.42.42"
		},
		{
			.type = DNSTYPE_MX,
			.key = "mxtestother.example.net",
			.value = "::ffff:10.42.42.40"
		},
		{
			.type = DNSTYPE_MX,
			.key = "mxtest6.example.net",
			.value = "::ffff:10.42.42.40;cafe:babe::1"
		},
		{
			.type = DNSTYPE_MX,
			.key = "mxtest6b.example.net",
			.value = "::ffff:10.42.42.48;cafe:babe::42;::ffff:10.42.42.40"
		},
		{
			.type = DNSTYPE_A,
			.key = "mxtest2.example.net",
			.value = "::ffff:10.42.42.43"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "expmakro.example.net",
			.value = "This should be percent-space-percent20: %%%_%-"
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		}
	};
	const char *mxinvalid[] = {
		"v=spf1 mx//",
		"v=spf1 mx/a/12",
		"v=spf1 mx/12/12",
		"v=spf1 mx/12//12a",
		"v=spf1 mx/34",
		"v=spf1 mx//140",
		"v=spf1 mx///64",
		"v=spf1 mx/0",
		"v=spf1 mx:",
		"v=spf1 mx: all",
		NULL
	};
	const char *mxvalid[] = {
		"v=spf1 mx/31 -all",
		"v=spf1 mx//12 -all",
		"v=spf1 mx/12//64 -all",
		"v=spf1 mx -all",
		"v=spf1 mx:mxtestother.example.net/24 -all",
		NULL
	};
	const char *mxvalid_reject[] = {
		"v=spf1 -ip4:10.42.42.42 mx -all",
		"v=spf1 mx:mxtest2.example.net/24 -all exp=expmakro.example.net",
		NULL
	};
	const char *mxvalid6[] = {
		"v=spf1 mx:mxtest6.example.net//64 -all",
		"v=spf1 mx:mxtest6b.example.net -all",
		NULL
	};
	int err = 0;
	unsigned int i = 0;
	int r;

	dnsdata = mxentries;
	i = 0;

	inet_pton(AF_INET6, "::ffff:10.42.42.42", &xmitstat.sremoteip);

	while (mxinvalid[i] != NULL) {
		mxentries[0].value = mxinvalid[i];

		r = check_host(mxentries[0].key);
		if (r != SPF_FAIL_MALF) {
			fprintf(stderr, "check_host() did not reject invalid MX entry '%s' as malformed, but returned %i\n", mxinvalid[i], r);
			err++;
		}

		i++;
	}

	i = 0;

	while (mxvalid[i] != NULL) {
		mxentries[0].value = mxvalid[i];

		r = check_host(mxentries[0].key);
		if (r != SPF_PASS) {
			fprintf(stderr, "check_host() did not accept '%s', but returned %i\n", mxvalid[i], r);
			err++;
		}

		i++;
	}

	i = 0;

	while (mxvalid_reject[i] != NULL) {
		mxentries[0].value = mxvalid_reject[i];

		r = check_host(mxentries[0].key);
		if (r != SPF_FAIL_PERM) {
			fprintf(stderr, "check_host() did not properly reject '%s', but returned %i\n", mxvalid_reject[i], r);
			err++;
		}

		free(xmitstat.spfexp);
		xmitstat.spfexp = NULL;

		i++;
	}

	i = 0;

	inet_pton(AF_INET6, "cafe:babe::42", &xmitstat.sremoteip);

	while (mxvalid6[i] != NULL) {
		mxentries[0].value = mxvalid6[i];

		r = check_host(mxentries[0].key);
		if (r != SPF_PASS) {
			fprintf(stderr, "check_host() did not accept '%s', but returned %i\n", mxvalid6[i], r);
			err++;
		}

		i++;
	}

	return err;
}

struct suite_testcase {
	const char *name;
	const char *helo;
	const char *remoteip;
	const char *mailfrom;
	const char *exp;
	int result;
};

static int
run_suite_test(const struct suite_testcase *testcases)
{
	unsigned int i = 0;
	int err = 0;

	newstr(&heloname, strlen("myhelo.example.net"));
	memcpy(heloname.s, "myhelo.example.net", strlen("myhelo.example.net"));

	while (testcases[i].helo != NULL) {
		int r;

		setup_transfer(testcases[i].helo, testcases[i].mailfrom, testcases[i].remoteip);

		r = check_host(strchr(testcases[i].mailfrom, '@') + 1);

		if (r != testcases[i].result) {
			fprintf(stderr, "makro test %s returned %i but %i was expected\n", testcases[i].name, r, testcases[i].result);
			err++;
		}

		if (testcases[i].exp != NULL) {
			if (xmitstat.spfexp == NULL) {
				fprintf(stderr, "Test %s should return SPF exp, but it did not\n", testcases[i].name);
				err++;
			} else if (strcmp(xmitstat.spfexp, testcases[i].exp) != 0) {
				fprintf(stderr, "Test %s did not return the expected SPF exp, but %s\n", testcases[i].name, xmitstat.spfexp);
				err++;
			}
		} else if ((xmitstat.spfexp != NULL) && (r != SPF_FAIL_MALF)) {
			/* hard error writes what it didn't understand into spfexp */

			fprintf(stderr, "no SPF exp was expected for test %s, but %s was returned\n", testcases[i].name, xmitstat.spfexp);
			err++;
		}

		free(xmitstat.remotehost.s);
		free(xmitstat.mailfrom.s);
		free(xmitstat.helostr.s);
		free(xmitstat.spfexp);
		xmitstat.spfexp = NULL;

		i++;
	}
	memset(&xmitstat, 0, sizeof(xmitstat));

	free(heloname.s);
	STREMPTY(heloname);

	return err;
}

static int
test_suite_makro()
{
	/* makro expansion tests taken from SPF test suite 2009.10
	 * http://www.openspf.org/svn/project/test-suite/rfc4408-tests-2009.10.yml */
	const struct dnsentry makroentries[] = {
		{
			.type = DNSTYPE_SPF,
			.key = "example.com.d.spf.example.com",
			.value = "v=spf1 redirect=a.spf.example.com"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "a.spf.example.com",
			.value = "v=spf1 include:o.spf.example.com. ~all"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "o.spf.example.com",
			.value = "v=spf1 ip4:192.168.218.40"
		},
		{
			.type = DNSTYPE_A,
			.key = "msgbas2x.cos.example.com",
			.value = "::ffff:192.168.218.40"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "example.com",
			.value = "v=spf1 redirect=%{d}.d.spf.example.com."
		},
		{
			.type = DNSTYPE_A,
			.key = "example.com",
			.value = "::ffff:192.168.90.76"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "exp.example.com",
			.value = "v=spf1 exp=msg.example.com. -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "msg.example.com",
			.value = "This is a test."
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e1.example.com",
			.value = "v=spf1 -exists:%(ir).sbl.example.com ?all"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e1a.example.com",
			.value = "v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"
		},
		{
			.type = DNSTYPE_A,
			.key = "macro%percent  space%20url-space.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e2.example.com",
			.value = "v=spf1 -all exp=%{r}.example.com"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e3.example.com",
			.value = "v=spf1 -all exp=%{ir}.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "40.218.168.192.example.com",
			.value = "Connections from %{c} not authorized."
		},
		{
			.type = DNSTYPE_SPF,
			.key = "somewhat.long.exp.example.com",
			.value = "v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com",
			.value = "Congratulations!  That was tricky."
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e4.example.com",
			.value = "v=spf1 -all exp=e4msg.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e4msg.example.com",
			.value = "%{c} is queried as %{ir}.%{v}.arpa"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e5.example.com",
			.value = "v=spf1 a:%{a}.example.com -all"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e6.example.com",
			.value = "v=spf1 -all exp=e6msg.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e6msg.example.com",
			.value = "connect from %{p}"
		},
		{
			.type = DNSTYPE_A,
			.key = "mx.example.com",
			.value = "::ffff:192.168.218.41,::ffff:192.168.218.42"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "mx.example.com",
			.value = "CAFE:BABE::2,CAFE:BABE::3"
		},
		{
			.type = DNSTYPE_NAME,
			.key = "::ffff:192.168.218.40",
			.value = "mx.example.com"
		},
		{
			.type = DNSTYPE_NAME,
			.key = "::ffff:192.168.218.41",
			.value = "mx.example.com"
		},
		{
			.type = DNSTYPE_NAME,
			.key = "::ffff:192.168.218.42",
			.value = "mx.example.com,mx.e7.example.com"
		},
		{
			.type = DNSTYPE_NAME,
			.key = "cafe:babe::1",
			.value = "mx.example.com"
		},
		{
			.type = DNSTYPE_NAME,
			.key = "cafe:babe::3",
			.value = "mx.example.com"
		},
		{
			.type = DNSTYPE_A,
			.key = "mx.e7.example.com",
			.value = "192.168.218.42"
		},
		{
			.type = DNSTYPE_A,
			.key = "mx.e7.example.com.should.example.com",
			.value = "127.0.0.2"
		},
		{
			.type = DNSTYPE_A,
			.key = "mx.example.com.ok.example.com",
			.value = "127.0.0.2"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e7.example.com",
			.value = "v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e8.example.com",
			.value = "v=spf1 -all exp=msg8.%{D2}"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "msg8.example.com",
			.value = "http://example.com/why.html?l=%{L}"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e9.example.com",
			.value = "v=spf1 a:%{H} -all"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e10.example.com",
			.value = "v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "_spfh.example.com",
			.value = "v=spf1 -a:%{h} +all"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e11.example.com",
			.value = "v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"
		},
		{
			.type = DNSTYPE_A,
			.key = "1.2.3.4.gladstone.philip.user.example.com",
			.value = "127.0.0.2"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e12.example.com",
			.value = "v=spf1 exists:%{l2r+-}.user.%{d2}"
		},
		{
			.type = DNSTYPE_A,
			.key = "bar.foo.user.example.com",
			.value = "127.0.0.2"
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		}
	};
	const struct suite_testcase makrotestcases[] = {
		{
			.name = "trailing-dot-domain",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.name = "trailing-dot-exp",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@exp.example.com",
			.exp = "This is a test.",
			.result = SPF_FAIL_PERM
		},
#if 0
		{
			.name = "exp-only-macro-char",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@e2.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
#endif
		{
			.name = "invalid-macro-char",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@e1.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
#if 0
		{
			.name = "macro-mania-in-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "test@e1a.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
#endif
		{
			.name = "exp-txt-macro-char",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@e3.example.com",
			.exp = "Connections from 192.168.218.40 not authorized.",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "domain-name-truncation",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@somewhat.long.exp.example.com",
			.exp = "Congratulations!  That was tricky.",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "v-macro-ip4",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@e4.example.com",
			.exp = "192.168.218.40 is queried as 40.218.168.192.in-addr.arpa",
			.result = SPF_FAIL_PERM
		},
		{
			/* Note: the dotted IP address is converted to lowercase in the exp string
			 * as my implementation uses lowercase and I can't see any reason why that
			 * shouldn't be as valid as uppercase. */
			.name = "v-macro-ip6",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "CAFE:BABE::1",
			.mailfrom = "test@e4.example.com",
			.exp = "cafe:babe::1 is queried as 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.b.a.b.e.f.a.c.ip6.arpa",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "undef-macro",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "CAFE:BABE::192.168.218.40",
			.mailfrom = "test@e5.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
#if 0
		{
			.name = "upper-macro",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.42",
			.mailfrom = "jack&jill=up@e8.example.com",
			.exp = "http://example.com/why.html?l=jack%26jill%3Dup",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "hello-macro",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "jack&jill=up@e9.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.name = "require-valid-helo",
			.helo = "OEMCOMPUTER",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "test@e10.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
#endif
		{
			.name = "macro-reverse-split-on-dash",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "philip-gladstone-test@e11.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.name = "macro-multiple-delimiters",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo-bar+zip+quux@e12.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.helo = NULL,
			.remoteip = NULL,
			.mailfrom = NULL,
			.exp = NULL,
			.result = -1
		}
	};

	dnsdata = makroentries;

	return run_suite_test(makrotestcases);
}

static int
test_suite_all()
{
	/* ALL mechanism syntax tests taken from SPF test suite 2009.10
	 * http://www.openspf.org/svn/project/test-suite/rfc4408-tests-2009.10.yml */
	const struct dnsentry allentries[] = {
		{
			.type = DNSTYPE_A,
			.key = "mail.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e1.example.com",
			.value = "v=spf1 -all."
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e2.example.com",
			.value = "v=spf1 -all:foobar"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e3.example.com",
			.value = "v=spf1 -all/8"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e4.example.com",
			.value = "v=spf1 ?all"
		},
		{
			.type = DNSTYPE_SPF,
			.key = "e5.example.com",
			.value = "v=spf1 all -all"
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		},
	};
	const struct suite_testcase alltestcases[] = {
		{
			.name = "all-dot",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e1.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "all-arg",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e2.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "all-cidr",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e3.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "all-neutral",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e4.example.com",
			.exp = NULL,
			.result = SPF_NEUTRAL
		},
		{
			.name = "all-double",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e5.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.helo = NULL,
			.remoteip = NULL,
			.mailfrom = NULL,
			.exp = NULL,
			.result = -1
		}
	};

	dnsdata = allentries;

	return run_suite_test(alltestcases);
}

static int
test_parse()
{
	const struct dnsentry parseentries[] = {
		{
			.type = DNSTYPE_TXT,
			.key = "recurse.example.net",
			.value = "v=spf1 include:recurse.example.net"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "recursebad.example.net",
			.value = "v=spf1 include:bad.example.net"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "othertext.example.net",
			.value = "random text entry"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "doublespf.example.net",
			.value = "v=spf1 ~all v=spf1 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "emptyspec.example.net",
			.value = "v=spf1  "
		},
		{
			.type = DNSTYPE_TXT,
			.key = "allneutral.example.net",
			.value = "v=spf1 ?all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "allfail.example.net",
			.value = "v=spf1 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "allsoftfail.example.net",
			.value = "v=spf1 ~all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "allpass.example.net",
			.value = "v=spf1 +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "allpassnoprefixupcase.example.net",
			.value = "v=spf1 ALL"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalidchar.example.net",
			.value = "v=spf1 !ALL"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "redirect-softfail.example.net",
			.value = " v=spf1 redirect=allsoftfail.example.net"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-mechanism.example.net",
			.value = "v=spf1 mxa +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-characters.example.net",
			.value = "v=spf1 mx(ö) +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "double-prefix.example.net",
			.value = "v=spf1 --mx +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-makro1.example.net",
			.value = "v=spf1 mx:%a +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-makro2.example.net",
			.value = "v=spf1 mx:%a{b} +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-makro3.example.net",
			.value = "v=spf1 mx:%{ab} +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-makro4.example.net",
			.value = "v=spf1 mx:%{h0} +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-makro5.example.net",
			.value = "v=spf1 mx:%{h2 +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-makro6.example.net",
			.value = "v=spf1 mx:%{h2rr} +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-makro7.example.net",
			.value = "v=spf1 mx:%{h2rr} +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-makro8.example.net",
			.value = "v=spf10 +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-makro9.example.net",
			.value = "v=spf1 mx:\020b +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-redirect-makro1.example.net",
			.value = "v=spf1 redirect=foo.example.com/"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-redirect-makro2.example.net",
			.value = "v=spf1 redirect=foo.example.com/16"
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		}
	};
	static int spfresults[] = {
		SPF_FAIL_MALF,
		SPF_FAIL_NONEX,
		SPF_NONE,
		SPF_FAIL_MALF,
		SPF_NEUTRAL,
		SPF_NEUTRAL,
		SPF_FAIL_PERM,
		SPF_SOFTFAIL,
		SPF_PASS,
		SPF_PASS,
		SPF_FAIL_MALF,
		SPF_SOFTFAIL,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF
	};
	int err = 0;
	unsigned int i = 0;
	int r;
	struct in6_addr sender_ip4;
	struct in6_addr sender_ip6;
	const char myhelo[] = "spftesthost.example.org";
	const char mailfrom[] = "localpart@spfsender.example.net";

	inet_pton(AF_INET6, "::ffff:10.42.42.42", &sender_ip4);
	inet_pton(AF_INET6, "fef0::abc:001", &sender_ip6);

	dnsdata = parseentries;
	memset(&xmitstat, 0, sizeof(xmitstat));
	if (newstr(&xmitstat.helostr, strlen(parseentries[0].key)))
		return ENOMEM;
	memcpy(xmitstat.helostr.s, parseentries[0].key, strlen(parseentries[0].key));
	memcpy(&xmitstat.sremoteip, &sender_ip6, sizeof(sender_ip6));
	newstr(&heloname, strlen(myhelo));
	memcpy(heloname.s, myhelo, strlen(myhelo));
	newstr(&xmitstat.mailfrom, strlen(mailfrom));
	memcpy(xmitstat.mailfrom.s, mailfrom, strlen(mailfrom));

	r = check_host("nonexistent.example.org");
	if (r != SPF_NONE) {
		fprintf(stderr, "check_host() without SPF entry SPF_NONE, but %i\n", r);
		err++;
	}

	r = check_host("garbage..domain");
	if (r != SPF_FAIL_MALF) {
		fprintf(stderr, "check_host() with invalid domain did not fail with SPF_FAIL_MALF, but %i\n", r);
		err++;
	}
	err += check_received(SPF_FAIL_MALF, 0);

	while (parseentries[i].key != NULL) {
		int c;

		r = check_host(parseentries[i].key);
		if (r != spfresults[i]) {
			fprintf(stderr, "check_host() for test %s should return %i, but did %i\n", parseentries[i].key, spfresults[i], r);
			err++;
		}
		c = check_received(r, 0);
		if (c != 0) {
			fprintf(stderr, "spfreceived() for test %s (status %i) returned %i\n", parseentries[i].key, r, c);
			err++;
		}
		i++;
		free(xmitstat.spfexp);
		xmitstat.spfexp = NULL;
	}

	err += test_parse_ip4();
	err += test_parse_ip6();
	err += test_parse_mx();

	free(xmitstat.helostr.s);
	STREMPTY(xmitstat.helostr);
	free(xmitstat.mailfrom.s);
	STREMPTY(xmitstat.mailfrom);
	free(heloname.s);
	STREMPTY(heloname);

	return err;
}

static int
test_received()
{
	int err = 0;
	unsigned int i = 0;
	struct in6_addr sender_ip4;
	struct in6_addr sender_ip6;
	const char myhelo[] = "spftesthost.example.org";
	const char mailfrom[] = "localpart@spfsender.example.net";
	const char *mechanism[] = { "MX", "A", "IP4", "default", NULL };

	inet_pton(AF_INET6, "::ffff:10.42.42.42", &sender_ip4);
	inet_pton(AF_INET6, "fef0::abc:001", &sender_ip6);

	memset(&xmitstat, 0, sizeof(xmitstat));
	if (newstr(&xmitstat.helostr, strlen(strchr(mailfrom, '@') + 1)))
		return ENOMEM;
	memcpy(xmitstat.helostr.s, strchr(mailfrom, '@') + 1, strlen(strchr(mailfrom, '@') + 1));
	memcpy(&xmitstat.sremoteip, &sender_ip6, sizeof(sender_ip6));
	newstr(&heloname, strlen(myhelo));
	memcpy(heloname.s, myhelo, strlen(myhelo));
	newstr(&xmitstat.mailfrom, strlen(mailfrom));
	memcpy(xmitstat.mailfrom.s, mailfrom, strlen(mailfrom));

	for (i = SPF_NONE; i <= SPF_HARD_ERROR; i++) {
		memcpy(&xmitstat.sremoteip, &sender_ip6, sizeof(sender_ip6));
		xmitstat.spfmechanism = mechanism[(i * 2) % 5];
		err += check_received(i, 1);
		memcpy(&xmitstat.sremoteip, &sender_ip4, sizeof(sender_ip4));
		xmitstat.spfmechanism = mechanism[(i * 2 + 1) % 5];
		err += check_received(i, 1);
	}

	/* these have not been tested before so do some explicit tests */
	err += check_received(SPF_IGNORE, 1);

	free(xmitstat.helostr.s);
	STREMPTY(xmitstat.helostr);
	free(xmitstat.mailfrom.s);
	STREMPTY(xmitstat.mailfrom);
	free(heloname.s);
	STREMPTY(heloname);

	return err;
}

static int
test_suite(void)
{
	int err = 0;

	err += test_suite_makro();
	err += test_suite_all();

	return err;
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return EINVAL;

	if (strcmp(argv[1], "redhat") == 0)
		return runtest(&spftest_redhat);
	else if (strcmp(argv[1], "sf-mail") == 0)
		return runtest(&spftest_sfmail);
	else if (strcmp(argv[1], "_parse_") == 0)
		return test_parse();
	else if (strcmp(argv[1], "_received_") == 0)
		return test_received();
	else if (strcmp(argv[1], "_suite_") == 0)
		return test_suite();
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

