/** \file spf_test.c
 \brief SPF testcases
 */

#include <mime_chars.h>
#include <qremote/mime.h> /* for skipwhitespace() */
#include <qremote/qremote.h> /* for write_status(), required by mime */
#include <qsmtpd/antispam.h>
#include <qsmtpd/qsmtpd.h>
#include <sstring.h>
#include "test_io/testcase_io.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

void
write_status(const char *str)
{
	puts(str);
	exit(EFAULT);
}

enum dnstype {
	DNSTYPE_A,
	DNSTYPE_AAAA,
	DNSTYPE_MX,
	DNSTYPE_NAME,
	DNSTYPE_TXT,
	DNSTYPE_TIMEOUT,
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

static struct in6_addr *
parsein6(const char *list, int *cnt)
{
	const char *next = list;
	struct in6_addr *ret = NULL;

	*cnt = 0;

	while (next != NULL) {
		char curbuf[INET6_ADDRSTRLEN];
		const char *parsep;
		char *end = strchr(next, ';');
		struct in6_addr *n;

		*cnt += 1;
		n = realloc(ret, *cnt * sizeof(*n));

		if (n == NULL) {
			free(ret);
			exit(ENOMEM);
		}
		ret = n;

		if (end == NULL) {
			parsep = next;
		} else {
			assert((size_t)(end - next) < sizeof(curbuf));
			strncpy(curbuf, next, end - next);
			curbuf[end - next] = '\0';
			         parsep = curbuf;
			end++;
		}

		if (inet_pton(AF_INET6, parsep, n + (*cnt - 1)) != 1) {
			fprintf(stderr, "%s can not be parsed as IPv6 address\n", parsep);
			exit(EINVAL);
		}

		next = end;
	}

	return ret;
}

int
test_ask_dnsmx(const char *domain, struct ips **ips)
{
	const char *value = dnsentry_search(DNSTYPE_MX, domain);

	*ips = NULL;
	if (value == NULL) {
		struct in6_addr *a;
		int r = ask_dnsa(domain, &a);
		struct in6_addr *ip6addr;
		int q = ask_dnsaaaa(domain, &ip6addr);

		if (dnsentry_search(DNSTYPE_TIMEOUT, domain) != NULL)
			return DNS_ERROR_TEMP;

		if (r > 0) {
			*ips = in6_to_ips(a, r, MX_PRIORITY_IMPLICIT);
			if (*ips == NULL) {
				free(ip6addr);
				return DNS_ERROR_LOCAL;
			}

			if (q > 0)
				(*ips)->next = in6_to_ips(ip6addr, q, MX_PRIORITY_IMPLICIT);
		} else if (q > 0) {
			*ips = in6_to_ips(ip6addr, q, MX_PRIORITY_IMPLICIT);
		}

		if ((q >= 0) && (r >= 0))
			return 0;
		else if (q >= 0)
			return 0;
		else
			return r;
	} else {
		const char *end = strchr(value, ';');

		if (end == NULL)
			end = value + strlen(value);

		do {
			char namebuf[256];
			const size_t l = end - value;
			struct ips *t;
			struct in6_addr *ipa;
			int cnt;

			assert(l < sizeof(namebuf));
			assert(l > 0);
			strncpy(namebuf, value, l);
			namebuf[l] = '\0';

			cnt = ask_dnsaaaa(namebuf, &ipa);
			if (cnt < 0) {
				freeips(*ips);
				*ips = NULL;
				return cnt;
			}

			if (cnt > 0) {
				t = in6_to_ips(ipa, cnt, 42);
				if (t == NULL) {
					freeips(*ips);
					*ips = NULL;
					return DNS_ERROR_LOCAL;
				}

				t->next = *ips;
				*ips = t;
			}

			if (*end == '\0') {
				end = NULL;
			} else {
				value = end + 1;
				end = strchr(value, ';');
				if (end == NULL)
					end = value + strlen(value);
			}
		} while (end != NULL);
	}

	return 0;
}

int
test_ask_dnsaaaa(const char *domain, struct in6_addr **ips)
{
	const char *value = dnsentry_search(DNSTYPE_AAAA, domain);
	struct in6_addr *cur, *n;
	int r;
	int m;

	if (value == NULL)
		return ask_dnsa(domain, ips);

	*ips = parsein6(value, &r);

	m = ask_dnsa(domain, &cur);

	if (m > 0) {
		n = realloc(*ips, (r + m) * sizeof(*n));
		if (n == NULL) {
			free(*ips);
			free(cur);
			return DNS_ERROR_LOCAL;
		}

		memcpy(n + r, cur, m * sizeof(*n));
		free(cur);
		*ips = n;
	}

	return r + m;
}

int
test_ask_dnsa(const char *domain, struct in6_addr **ips)
{
	const char *value = dnsentry_search(DNSTYPE_A, domain);
	int r;
	struct in6_addr *q;

	if (value == NULL) {
		if (dnsentry_search(DNSTYPE_TIMEOUT, domain) != NULL)
			return DNS_ERROR_TEMP;

		return 0;
	}

	q = parsein6(value, &r);
	if (ips != NULL)
		*ips = q;
	else
		free(q);

	return r;
}

int
test_ask_dnsname(const struct in6_addr *addr, char **name)
{
	char iptmp[INET6_ADDRSTRLEN];
	size_t l;
	int cnt = 0;

	inet_ntop(AF_INET6, addr, iptmp, sizeof(iptmp));

	const char *value = dnsentry_search(DNSTYPE_NAME, iptmp);

	if (value == NULL) {
		if (dnsentry_search(DNSTYPE_TIMEOUT, iptmp) != NULL)
			return -2;

		return 0;
	}

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

static int
dns_resolve_txt(char **out, const char *host, const enum dnstype stype)
{
	const char *value = dnsentry_search(stype, host);

	if (value == NULL) {
		if (dnsentry_search(DNSTYPE_TIMEOUT, host) != NULL)
			errno = ETIMEDOUT;
		else
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
	return dns_resolve_txt(out, host, DNSTYPE_TXT);
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
	.goodip = "::ffff:192.0.2.61",
	.badip = "::ffff:192.0.2.62",
	.dns = {
		{
			.type = DNSTYPE_A,
			.key = "mx.sf-mail.de",
			.value = "::ffff:192.0.2.61"
		},
		{
			.type = DNSTYPE_MX,
			.key = "sf-mail.de",
			.value = "mx.sf-mail.de"
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
static const char defaulthelo[] = "myhelo.example.net";

static int
init_helo(const char *helo)
{
	if (newstr(&heloname, strlen(helo)) != 0)
		return ENOMEM;
	memcpy(heloname.s, helo, strlen(helo));
	return 0;
}

static int
check_received(int spfstatus, int log)
{
	int fd[2];
	char buf[1024];
	int r;
	size_t off = 0;
	const char hdrline[] = "Received-SPF: ";
	const char *spfstates[] = { "pass", "fail", "softfail", "none", "neutral", "temperror", "permerror", NULL };
	const char *tmp;

	if ((spfstatus < SPF_NONE) || ((spfstatus > SPF_HARD_ERROR) && (spfstatus != SPF_IGNORE))) {
		fprintf(stderr, "invalid SPF status code: %i\n", spfstatus);
		return 1;
	}

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
		const char percentwarn[] = "unsafe characters may have been replaced by '%'";
		const char *percentmatch;
		int mismatch = 0;

		/* If '%' is in the message, then the warning message has to be, too.
		 * If no '%' is in the message, then no warning message should be there. */
		percentmatch = strstr(tmp, percentwarn);
		if (percentmatch != NULL) {
			/* there should be no % signns before the warning, but some after */
			if (memchr(tmp, '%', percentmatch - tmp) != NULL) {
				fprintf(stderr, "unexpected %% characters before the warning message: %s\n",
					tmp);
				return 1;
			}
			mismatch = (strchr(percentmatch + strlen(percentwarn), '%') == NULL);
		} else {
			mismatch = (strchr(buf, '%') != NULL);
		}

		if (mismatch) {
			fprintf(stderr, "'%%' character and warning message mismatch: %s\n", tmp);
			return 1;
		}
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
		if (strncmp(tmp, "x-", 2) == 0) {
			tmp += 2;
			while ((*tmp != '\n') && (*tmp != '='))
				tmp++;
		} else {
			const char *spfkey[] = { "client-ip", "envelope-from", "helo",
					"problem", "receiver", "identity", "mechanism", NULL };
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
					if (*(tmp + 1) == '\0')
						break;

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

	if (newstr(&xmitstat.mailfrom, (from == NULL) ? 0 : strlen(from)))
		exit(ENOMEM);

	if (newstr(&xmitstat.helostr, strlen(helo)))
		exit(ENOMEM);

	if (from != NULL)
		memcpy(xmitstat.mailfrom.s, from, strlen(from));
	memcpy(xmitstat.helostr.s, helo, strlen(helo));

	assert(strlen(remoteip) < sizeof(xmitstat.remoteip));
	strncpy(xmitstat.remoteip, remoteip, sizeof(xmitstat.remoteip));
	if (inet_pton(AF_INET6, remoteip, &xmitstat.sremoteip) != 1) {
		fprintf(stderr, "can not parse %s as IPv6 address for mailfrom %s\n", remoteip, from);
		exit(EINVAL);
	}
	xmitstat.ipv4conn = IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip) ? 1 : 0;

	if (ask_dnsname(&xmitstat.sremoteip, &xmitstat.remotehost.s) > 0)
		xmitstat.remotehost.len = strlen(xmitstat.remotehost.s);
}

static int
runtest(struct spftestcase *tc)
{
	int err = 0;

	setup_transfer(tc->helo, tc->from, tc->goodip);
	if (init_helo(defaulthelo) != 0)
		return ++err;

	dnsdata = tc->dns;

	int r = check_host(strchr(tc->from, '@') + 1);
	if (SPF_IS_FAILURE(r)) {
		fprintf(stderr, "good IP did not pass for %s\n", tc->helo);
		err++;
	}
	err += check_received(r, 0);

	if (tc->badip == NULL)
		return 0;

	assert(strlen(tc->badip) < sizeof(xmitstat.remoteip));
	strncpy(xmitstat.remoteip, tc->badip, sizeof(xmitstat.remoteip));
	inet_pton(AF_INET6, tc->badip, &xmitstat.sremoteip);
	xmitstat.ipv4conn = IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip) ? 1 : 0;

	r = check_host(strchr(tc->from, '@') + 1);
	if (!SPF_IS_FAILURE(r)) {
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
	free(heloname.s);
	STREMPTY(heloname);

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
	xmitstat.ipv4conn = 1;

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
	xmitstat.ipv4conn = 0;
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
	xmitstat.ipv4conn = 1;
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
	static const char toomany[] = "toomany.example.net";
	struct dnsentry mxentries[] = {
		{
			.type = DNSTYPE_TXT,
			.key = "mxtest.example.net",
			.value = NULL
		},
		{
			.type = DNSTYPE_MX,
			.key = "mxtest.example.net",
			.value = "mxtest.example.net"
		},
		{
			.type = DNSTYPE_A,
			.key = "mxtest.example.net",
			.value = "::ffff:10.42.42.42"
		},
		{
			.type = DNSTYPE_MX,
			.key = "mxtestother.example.net",
			.value = "mxtestother.example.net"
		},
		{
			.type = DNSTYPE_A,
			.key = "mxtestother.example.net",
			.value = "::ffff:10.42.42.40"
		},
		{
			.type = DNSTYPE_MX,
			.key = "mxtest6.example.net",
			.value = "mxtestother.example.net;mxtest6.example.net"
		},
		{
			.type = DNSTYPE_A,
			.key = "mxtest6.example.net",
			.value = "cafe:babe::1"
		},
		{
			.type = DNSTYPE_MX,
			.key = "mxtest6b.example.net",
			.value = "mxtest6b.example.net"
		},
		{
			.type = DNSTYPE_A,
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
			.type = DNSTYPE_MX,
			.key = toomany,
			.value = "mxtest.example.net;mxtest.example.net;"
					"mxtestother.example.net;mxtestother.example.net;"
					"mxtest6.example.net;mxtest6.example.net;mxtest6.example.net;"
					"mxtest6b.example.net;mxtest6b.example.net;mxtest6b.example.net;mxtest6b.example.net"
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
		"v=spf1 mx:",
		"v=spf1 mx:museum..",
		"v=spf1 mx:museum../8",
		"v=spf1 mx:foo\223.bar",
		"v=spf1 mx: all",
		NULL
	};
	const char *mxvalid[] = {
		"v=spf1 mx",
		"v=spf1 mx/31 -all",
		"v=spf1 mx//12 -all",
		"v=spf1 mx/12//64 -all",
		"v=spf1 mx/0",
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
	xmitstat.ipv4conn = 1;

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
	xmitstat.ipv4conn = 0;

	while (mxvalid6[i] != NULL) {
		mxentries[0].value = mxvalid6[i];

		r = check_host(mxentries[0].key);
		if (r != SPF_PASS) {
			fprintf(stderr, "check_host() did not accept '%s', but returned %i\n", mxvalid6[i], r);
			err++;
		}

		i++;
	}

	mxentries[0].key = toomany;
	mxentries[0].value = mxvalid[0];
	r = check_host(toomany);
	if (r != SPF_FAIL_PERM) {
		fprintf(stderr, "check_host(toomany.example.net) did not reject with permanent error, but returned %i\n", r);
		err++;
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

	if (init_helo(defaulthelo) != 0)
		return ++err;

	while (testcases[i].helo != NULL) {
		int r;
		const char *domain = (testcases[i].mailfrom != NULL) ? strchr(testcases[i].mailfrom, '@') + 1 : testcases[i].helo;

		setup_transfer(testcases[i].helo, testcases[i].mailfrom, testcases[i].remoteip);

		r = check_host(domain);

		if (r != testcases[i].result) {
			fprintf(stderr, "Test %s returned %i but %i was expected\n", testcases[i].name, r, testcases[i].result);
			err++;
		}

		if (testcases[i].exp != NULL) {
			if (xmitstat.spfexp == NULL) {
				fprintf(stderr, "Test %s should return SPF exp '%s', but it did not\n", testcases[i].name, testcases[i].exp);
				err++;
			} else if (strcmp(xmitstat.spfexp, testcases[i].exp) != 0) {
				fprintf(stderr, "Test %s did not return the expected SPF exp '%s', but '%s'\n",
						testcases[i].name, testcases[i].exp, xmitstat.spfexp);
				err++;
			}
		} else if (xmitstat.spfexp != NULL) {
			if (r != SPF_FAIL_MALF) {
				/* hard error writes what it didn't understand into spfexp,
				 * but that will never contain whitespace */
				fprintf(stderr, "Test %s: no SPF exp was expected, but %s was returned\n", testcases[i].name, xmitstat.spfexp);
				err++;
			} else if (strchr(xmitstat.spfexp, ' ') != NULL) {
				fprintf(stderr, "Test %s: exp record was not ignored on parse error: '%s'\n", testcases[i].name, xmitstat.spfexp);
				err++;
			}
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
	/* All SPF records have been replaced by TXT records as SPF DNS records
	 * are considered depcrecated. */
	const struct dnsentry makroentries[] = {
		{
			.type = DNSTYPE_TXT,
			.key = "example.com.d.spf.example.com",
			.value = "v=spf1 redirect=a.spf.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "a.spf.example.com",
			.value = "v=spf1 include:o.spf.example.com. ~all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "o.spf.example.com",
			.value = "v=spf1 ip4:192.168.218.40"
		},
		{
			.type = DNSTYPE_A,
			.key = "msgbas2x.cos.example.com",
			.value = "::ffff:192.168.218.40"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "example.com",
			.value = "v=spf1 redirect=%{d}.d.spf.example.com."
		},
		{
			.type = DNSTYPE_A,
			.key = "example.com",
			.value = "::ffff:192.168.90.76"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "exp.example.com",
			.value = "v=spf1 exp=msg.example.com. -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "msg.example.com",
			.value = "This is a test."
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e1.example.com",
			.value = "v=spf1 -exists:%(ir).sbl.example.com ?all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e1e.example.com",
			.value = "v=spf1 exists:foo%(ir).sbl.example.com ?all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e1t.example.com",
			.value = "v=spf1 exists:foo%.sbl.example.com ?all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e1a.example.com",
			.value = "v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"
		},
		{
			.type = DNSTYPE_A,
			.key = "macro%percent  space%20url-space.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e2.example.com",
			.value = "v=spf1 -all exp=%{r}.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e3.example.com",
			.value = "v=spf1 -all exp=%{ir}.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "40.218.168.192.example.com",
			.value = "Connections from %{c} not authorized."
		},
		{
			.type = DNSTYPE_TXT,
			.key = "somewhat.long.exp.example.com",
			.value = "v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com",
			.value = "Congratulations!  That was tricky."
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e4.example.com",
			.value = "v=spf1 -all exp=e4msg.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e4msg.example.com",
			.value = "%{c} is queried as %{ir}.%{v}.arpa"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e5.example.com",
			.value = "v=spf1 a:%{a}.example.com -all"
		},
		{
			.type = DNSTYPE_TXT,
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
			.value = "::ffff:192.168.218.41;::ffff:192.168.218.42"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "mx.example.com",
			.value = "CAFE:BABE::2;CAFE:BABE::3"
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
			.value = "mx.example.com;mx.e7.example.com"
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
			.value = "::ffff:192.168.218.42"
		},
		{
			.type = DNSTYPE_A,
			.key = "mx.e7.example.com.should.example.com",
			.value = "::ffff:127.0.0.2"
		},
		{
			.type = DNSTYPE_A,
			.key = "mx.example.com.ok.example.com",
			.value = "::ffff:127.0.0.2"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e7.example.com",
			.value = "v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e8.example.com",
			.value = "v=spf1 -all exp=msg8.%{D2}"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "msg8.example.com",
			.value = "http://example.com/why.html?l=%{L}"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e9.example.com",
			.value = "v=spf1 a:%{H} -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e10.example.com",
			.value = "v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "_spfh.example.com",
			.value = "v=spf1 -a:%{h} +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e11.example.com",
			.value = "v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"
		},
		{
			.type = DNSTYPE_A,
			.key = "1.2.3.4.gladstone.philip.user.example.com",
			.value = "::ffff:127.0.0.2"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e12.example.com",
			.value = "v=spf1 exists:%{l2r+-}.user.%{d2}"
		},
		{
			.type = DNSTYPE_A,
			.key = "bar.foo.user.example.com",
			.value = "::ffff:127.0.0.2"
		},
		{
			.type = DNSTYPE_NONE
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
		/* testsuite says result is hard error, but RfC 7208 says:
		 * "If [...] there are syntax errors in the explanation string,
		 * then proceed as if no "exp" modifier was given */
		{
			.name = "exp-only-macro-char",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@e2.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "invalid-macro-char",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@e1.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "invalid-embedded-macro-char",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@e1e.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.name = "invalid-trailing-macro-char",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@e1t.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.name = "macro-mania-in-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "test@e1a.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
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
		{
			.name = "p-macro-ip4-novalid",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@e6.example.com",
			.exp = "connect from unknown",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "p-macro-ip4-valid",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.41",
			.mailfrom = "test@e6.example.com",
			.exp = "connect from mx.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "p-macro-ip6-novalid",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "cafe:babe::1",
			.mailfrom = "test@e6.example.com",
			.exp = "connect from unknown",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "p-macro-ip6-valid",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "cafe:babe::3",
			.mailfrom = "test@e6.example.com",
			.exp = "connect from mx.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "p-macro-multiple",
			.helo = "msgbas2x.cos.example.com",
			.remoteip = "::ffff:192.168.218.42",
			.mailfrom = "test@e7.example.com",
			.exp = NULL,
			.result = SPF_SOFTFAIL /* or SPF_PASS */
		},
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
			.name = "invalid-hello-macro",
			.helo = "JUMPIN' JUPITER",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@e9.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "hello-domain-literal",
			.helo = "[192.168.218.40]",
			.remoteip = "::ffff:192.168.218.40",
			.mailfrom = "test@e9.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "require-valid-helo",
			.helo = "OEMCOMPUTER",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "test@e10.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
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
			.type = DNSTYPE_TXT,
			.key = "e1.example.com",
			.value = "v=spf1 -all."
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e2.example.com",
			.value = "v=spf1 -all:foobar"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e3.example.com",
			.value = "v=spf1 -all/8"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e4.example.com",
			.value = "v=spf1 ?all"
		},
		{
			.type = DNSTYPE_TXT,
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
test_suite_exists()
{
	/* Exists mechanism syntax tests taken from SPF test suite 2014.05
	 * http://www.openspf.org/svn/project/test-suite/rfc7208-tests-2014.05.yml */
	const struct dnsentry existsentries[] = {
		{
			.type = DNSTYPE_A,
			.key = "mail.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "mail6.example.com",
			.value = "CAFE:BABE::4"
		},
		{
			.type = DNSTYPE_TIMEOUT,
			.key = "err.example.com",
			.value = ""
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e1.example.com",
			.value = "v=spf1 exists:"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e2.example.com",
			.value = "v=spf1 exists"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e3.example.com",
			.value = "v=spf1 exists:mail.example.com/24"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e4.example.com",
			.value = "v=spf1 exists:mail.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e5.example.com",
			.value = "v=spf1 exists:mail6.example.com -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e6.example.com",
			.value = "v=spf1 exists:err.example.com -all"
		},
		{
			.type = DNSTYPE_NONE
		}
	};
	const struct suite_testcase existstestcases[] = {
		{
			.name = "exists-empty-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e1.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "exists-implicit",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e2.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "exists-cidr",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e3.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "exists-ip4",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e4.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.name = "exists-ip6",
			.helo = "mail.example.com",
			.remoteip = "CAFE:BABE::3",
			.mailfrom = "foo@e4.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.name = "exists-ip6only",
			.helo = "mail.example.com",
			.remoteip = "CAFE:BABE::3",
			.mailfrom = "foo@e5.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "exists-dnserr",
			.helo = "mail.example.com",
			.remoteip = "CAFE:BABE::3",
			.mailfrom = "foo@e6.example.com",
			.exp = NULL,
			.result = SPF_TEMP_ERROR
		},
		{
			.helo = NULL,
			.remoteip = NULL,
			.mailfrom = NULL,
			.exp = NULL,
			.result = -1
		}
	};

	dnsdata = existsentries;

	return run_suite_test(existstestcases);
}

static int
test_suite_mx()
{
	/* MX mechanism syntax tests taken from SPF test suite 2014.05
	 * http://www.openspf.org/svn/project/test-suite/rfc7208-tests-2014.05.yml */
	const struct dnsentry mxentries[] = {
		{
			.type = DNSTYPE_A,
			.key = "mail.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_MX,
			.key = "mail.example.com",
		},
		{
			.type = DNSTYPE_TXT,
			.key = "mail.example.com",
			.value = "v=spf1 mx"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e1.example.com",
			.value = "v=spf1 mx/0 -all"
		},
		{
			.type = DNSTYPE_MX,
			.key = "e1.example.com",
			.value = "e1.example.com"
		},
		{
			.type = DNSTYPE_A,
			.key = "e2.example.com",
			.value = "::ffff:1.1.1.1"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "e2.example.com",
			.value = "1234::2"
		},
		{
			.type = DNSTYPE_MX,
			.key = "e2.example.com",
			.value = "e2.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e2.example.com",
			.value = "v=spf1 mx/0 -all"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "e2a.example.com",
			.value = "1234::1"
		},
		{
			.type = DNSTYPE_MX,
			.key = "e2a.example.com",
			.value = "e2a.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e2a.example.com",
			.value = "v=spf1 mx//0 -all"
		},
		{
			.type = DNSTYPE_A,
			.key = "e2b.example.com",
			.value = "::ffff:1.1.1.1"
		},
		{
			.type = DNSTYPE_MX,
			.key = "e2b.example.com",
			.value = "e2b.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e2b.example.com",
			.value = "v=spf1 mx//0 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e3.example.com",
			.value = "v=spf1 mx:foo.example.com\0"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e4.example.com",
			.value = "v=spf1 mx"
		},
		{
			.type = DNSTYPE_A,
			.key = "e4.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e5.example.com",
			.value = "v=spf1 mx:abc.123"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e6.example.com",
			.value = "v=spf1 mx//33 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e6a.example.com",
			.value = "v=spf1 mx/33 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e7.example.com",
			.value = "v=spf1 mx//129 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e9.example.com",
			.value = "v=spf1 mx:example.com:8080"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e10.example.com",
			.value = "v=spf1 mx:foo.example.com/24"
		},
		{
			.type = DNSTYPE_MX,
			.key = "foo.example.com",
			.value = "foo1.example.com"
		},
		{
			.type = DNSTYPE_A,
			.key = "foo1.example.com",
			.value = "::ffff:1.1.1.1;::ffff:1.2.3.5"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e11.example.com",
			.value = "v=spf1 mx:foo:bar/baz.example.com"
		},
		{
			.type = DNSTYPE_MX,
			.key = "foo:bar/baz.example.com",
			.value = "foo:bar/baz.example.com"
		},
		{
			.type = DNSTYPE_A,
			.key = "foo:bar/baz.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e12.example.com",
			.value = "v=spf1 mx:example.-com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e13.example.com",
			.value = "v=spf1 mx: -all"
		},
		{
			.type = DNSTYPE_NONE
		}
	};
	const struct suite_testcase mxtestcases[] = {
		{
			.name = "mx-cidr6",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e6.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "mx-bad-cidr4",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e6a.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.name = "mx-bad-cidr6",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e7.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.name = "mx-multi-ip1",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e10.example.com",
			.result = SPF_PASS
		},
		{
			.name = "mx-multi-ip2",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e10.example.com",
			.result = SPF_PASS
		},
		{
			.name = "mx-bad-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e9.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.name = "mx-nxdomain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e1.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "mx-cidr4-0",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e2.example.com",
			.result = SPF_PASS
		},
		{
			.name = "mx-cidr4-0-ip6",
			.helo = "mail.example.com",
			.remoteip = "1234::1",
			.mailfrom = "foo@e2.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "mx-cidr6-0-ip4",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e2a.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "mx-cidr6-0-ip4mapped",
			.helo = "mail.example.com",
			.remoteip = "::FFFF:1.2.3.4",
			.mailfrom = "foo@e2a.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "mx-cidr6-0-ip6",
			.helo = "mail.example.com",
			.remoteip = "1234::1",
			.mailfrom = "foo@e2a.example.com",
			.result = SPF_PASS
		},
#if 0
		/* ip6/0 also matches all V4mapped IPv6 addresses */
		{
			.name = "mx-cidr6-0-nxdomain",
			.helo = "mail.example.com",
			.remoteip = "1234::1",
			.mailfrom = "foo@e2b.example.com",
			.result = SPF_FAIL_PERM
		},
		/* \0 in the string is not detected */
		{
			.name = "mx-null",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.5",
			.mailfrom = "foo@e3.example.com",
			.result = SPF_FAIL_MALF
		},
#endif
		{
			.name = "mx-numeric-top-label",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e5.example.com",
			.result = SPF_FAIL_MALF
		},
#if 0
		/* the same as mx-colon-domain-ip4mapped as this implementation is
		 * basically IPv6-only. */
		{
			.name = "mx-colon-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e11.example.com",
			.result = SPF_PASS
		},
		/* doesn't work because domain check is too strict. */
		{
			.name = "mx-colon-domain-ip4mapped",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e11.example.com",
			.result = SPF_PASS
		},
#endif
		{
			.name = "mx-bad-toplab",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e12.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.name = "mx-empty",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.result = SPF_NEUTRAL
		},
		{
			.name = "mx-implicit",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e4.example.com",
			.result = SPF_NEUTRAL
		},
		{
			.name = "mx-empty-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e13.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.result = -1
		}
	};

	dnsdata = mxentries;

	return run_suite_test(mxtestcases);
}

static int
test_suite_ptr()
{
	/* PTR mechanism syntax tests taken from SPF test suite 2009.10
	 * http://www.openspf.org/svn/project/test-suite/rfc4408-tests-2009.10.yml */
	const struct dnsentry ptrentries[] = {
		{
			.type = DNSTYPE_A,
			.key = "mail.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e1.example.com",
			.value = "v=spf1 ptr/0 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e2.example.com",
			.value = "v=spf1 ptr:example.com -all"
		},
		{
			.type = DNSTYPE_NAME,
			.key = "::ffff:1.2.3.4",
			.value = "e3.example.com;e4.example.com;mail.example.com"
		},
		{
			.type = DNSTYPE_NAME,
			.key = "cafe:babe::1",
			.value = "e3.example.com"
		},
		{
			.type = DNSTYPE_A,
			.key = "e3.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "e3.example.com",
			.value = "CAFE:BABE::1"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e3.example.com",
			.value = "v=spf1 ptr -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e4.example.com",
			.value = "v=spf1 ptr -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e5.example.com",
			.value = "v=spf1 ptr:"
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		},
	};
	const struct suite_testcase ptrtestcases[] = {
		{
			.name = "ptr-cidr",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e1.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "ptr-match-target",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e2.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.name = "ptr-match-implicit",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e3.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.name = "ptr-nomatch-invalid",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e4.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "ptr-match-ip6",
			.helo = "mail.example.com",
			.remoteip = "CAFE:BABE::1",
			.mailfrom = "foo@e3.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.name = "ptr-empty-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e5.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.helo = NULL,
			.remoteip = NULL,
			.mailfrom = NULL,
			.exp = NULL,
			.result = -1
		}
	};

	dnsdata = ptrentries;

	return run_suite_test(ptrtestcases);
}

static int
test_suite_a()
{
	/* A mechanism syntax tests taken from SPF test suite 2009.10
	 * http://www.openspf.org/svn/project/test-suite/rfc4408-tests-2009.10.yml */
	const struct dnsentry aentries[] = {
		{
			.type = DNSTYPE_A,
			.key = "mail.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e1.example.com",
			.value = "v=spf1 a/0 -all"
		},
		{
			.type = DNSTYPE_A,
			.key = "e2.example.com",
			.value = "::ffff:1.1.1.1"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "e2.example.com",
			.value = "1234::2"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e2.example.com",
			.value = "v=spf1 a/0 -all"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "e2a.example.com",
			.value = "1234::1"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e2a.example.com",
			.value = "v=spf1 a//0 -all"
		},
		{
			.type = DNSTYPE_A,
			.key = "e2b.example.com",
			.value = "::ffff:1.1.1.1"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e2b.example.com",
			.value = "v=spf1 a//0 -all"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "ipv6.example.com",
			.value = "1234::1"
		},
		{
			.type = DNSTYPE_A,
			.key = "ipv6.example.com",
			.value = "::ffff:1.1.1.1"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "ipv6.example.com",
			.value = "v=spf1 a -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e3.example.com",
			.value = "v=spf1 a:foo.example.com\0"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e4.example.com",
			.value = "v=spf1 a:111.222.33.44"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e5.example.com",
			.value = "v=spf1 a:abc.123"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e5a.example.com",
			.value = "v=spf1 a:museum"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e5b.example.com",
			.value = "v=spf1 a:museum."
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e6.example.com",
			.value = "v=spf1 a//33 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e6a.example.com",
			.value = "v=spf1 a/33 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e7.example.com",
			.value = "v=spf1 a//129 -all"
		},
		{
			.type = DNSTYPE_A,
			.key = "e8.example.com",
			.value = "::ffff:1.2.3.5"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "e8.example.com",
			.value = "2001:db8:1234::dead:beef"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e8.example.com",
			.value = "v=spf1 a/24//64 -all"
		},
		{
			.type = DNSTYPE_A,
			.key = "e8e.example.com",
			.value = "::ffff:1.2.3.5"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "e8e.example.com",
			.value = "2001:db8:1234::dead:beef"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e8e.example.com",
			.value = "v=spf1 a/24/64 -all"
		},
		{
			.type = DNSTYPE_A,
			.key = "e8a.example.com",
			.value = "::ffff:1.2.3.5"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "e8a.example.com",
			.value = "2001:db8:1234::dead:beef"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e8a.example.com",
			.value = "v=spf1 a/24 -all"
		},
		{
			.type = DNSTYPE_A,
			.key = "e8b.example.com",
			.value = "::ffff:1.2.3.5"
		},
		{
			.type = DNSTYPE_AAAA,
			.key = "e8b.example.com",
			.value = "2001:db8:1234::dead:beef"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e8b.example.com",
			.value = "v=spf1 a//64 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e9.example.com",
			.value = "v=spf1 a:example.com:8080"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e10.example.com",
			.value = "v=spf1 a:foo.example.com/24"
		},
		{
			.type = DNSTYPE_A,
			.key = "foo.example.com",
			.value = "::ffff:1.1.1.1;::ffff:1.2.3.5"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e11.example.com",
			.value = "v=spf1 a:foo:bar/baz.example.com"
		},
		{
			.type = DNSTYPE_A,
			.key = "foo:bar/baz.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e12.example.com",
			.value = "v=spf1 a:example.-com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e13.example.com",
			.value = "v=spf1 a:"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e14.example.com",
			.value = "v=spf1 a:foo.example.xn--zckzah -all"
		},
		{
			.type = DNSTYPE_A,
			.key = "foo.example.xn--zckzah",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		}
	};
	const struct suite_testcase atestcases[] = {
		{
			.name = "a-cidr6",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e6.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "a-bad-cidr4",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e6a.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "a-bad-cidr6",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e7.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "a-dual-cidr-ip4-match",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e8.example.com",
			.result = SPF_PASS
		},
		{
			.name = "a-dual-cidr-ip4-err",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e8e.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.name = "a-dual-cidr-ip6-match",
			.helo = "mail.example.com",
			.remoteip = "2001:db8:1234::cafe:babe",
			.mailfrom = "foo@e8.example.com",
			.result = SPF_PASS
		},
		{
			.name = "a-dual-cidr-ip4-default",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e8b.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "a-dual-cidr-ip6-default",
			.helo = "mail.example.com",
			.remoteip = "2001:db8:1234::cafe:babe",
			.mailfrom = "foo@e8a.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "a-multi-ip1",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e10.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			/* I still don't see how -ip1 and -ip2 differ */
			.name = "a-multi-ip2",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e10.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.name = "a-bad-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e9.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "a-nxdomain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e1.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "a-cidr4-0",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e2.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.name = "a-cidr4-0-ip6",
			.helo = "mail.example.com",
			.remoteip = "1234::1",
			.mailfrom = "foo@e2.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "a-cidr6-0-ip4",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e2a.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			/* since Qsmtp handles IPv4 connections alsways as IPv4mapped
			 * this is the same as a-cidr6-0-ip4 for us */
			.name = "a-cidr6-0-ip4mapped",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e2a.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "a-cidr6-0-ip6",
			.helo = "mail.example.com",
			.remoteip = "1234::1",
			.mailfrom = "foo@e2a.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.name = "a-cidr6-0-nxdomain",
			.helo = "mail.example.com",
			.remoteip = "1234::1",
			.mailfrom = "foo@e2b.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "a-ip6-dualstack",
			.helo = "mail.example.com",
			.remoteip = "1234::1",
			.mailfrom = "foo@ipv6.example.com",
			.result = SPF_PASS
		},
		{
			.name = "a-numeric",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e4.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "a-numeric-toplabel",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e5.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "a-bad-toplabel",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e12.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "a-only-toplabel",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e5a.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "a-only-toplabel-trailing-dot",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e5b.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
#if 0
		{
			.name = "a-colon-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e11.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
#endif
		{
			.name = "a-empty-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e11.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.helo = NULL,
			.remoteip = NULL,
			.mailfrom = NULL,
			.exp = NULL,
			.result = -1
		}
	};

	dnsdata = aentries;

	return run_suite_test(atestcases);
}

static int
test_suite_modifiers()
{
	/* Semantics of exp and other modifiers tests taken from SPF test suite 2014.05
	 * http://www.openspf.org/svn/project/test-suite/rfc7208-tests-2014.05.yml */
	const struct dnsentry modentries[] = {
		{
			.type = DNSTYPE_A,
			.key = "mail.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e1.example.com",
			.value = "v=spf1 exp=exp1.example.com redirect=e2.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e2.example.com",
			.value = "v=spf1 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e3.example.com",
			.value = "v=spf1 exp=exp1.example.com redirect=e4.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e4.example.com",
			.value = "v=spf1 -all exp=exp2.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "exp1.example.com",
			.value = "No-see-um"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "exp2.example.com",
			.value = "See me."
		},
		{
			.type = DNSTYPE_TXT,
			.key = "exp3.example.com",
			.value = "Correct!"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "exp4.example.com",
			.value = "%{l} in implementation"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e5.example.com",
			.value = "v=spf1 1up=foo"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e6.example.com",
			.value = "v=spf1 =all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e7.example.com",
			.value = "v=spf1 include:e3.example.com -all exp=exp3.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e8.example.com",
			.value = "v=spf1 -all exp=exp4.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e9.example.com",
			.value = "v=spf1 -all foo=%abc"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e10.example.com",
			.value = "v=spf1 redirect=erehwon.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e11.example.com",
			.value = "v=spf1 -all exp=e11msg.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e11msg.example.com",
			.value = "Answer a fool according to his folly."
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e11msg.example.com",
			.value = "Do not answer a fool according to his folly."
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e12.example.com",
			.value = "v=spf1 exp= -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e13.example.com",
			.value = "v=spf1 exp=e13msg.example.com -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e13msg.example.com",
			.value = "The %{x}-files."
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e14.example.com",
			.value = "v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e15.example.com",
			.value = "v=spf1 redirect=e12.example.com -all redirect=e12.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e16.example.com",
			.value = "v=spf1 exp=-all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e17.example.com",
			.value = "v=spf1 redirect=-all ?all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e18.example.com",
			.value = "v=spf1 ?all redirect="
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e19.example.com",
			.value = "v=spf1 default=pass"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e20.example.com",
			.value = "v=spf1 default=+"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e21.example.com",
			.value = "v=spf1 exp=e21msg.example.com -all"
		},
		{
			.type = DNSTYPE_TIMEOUT,
			.key = "e21msg.example.com",
			.value = ""
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e22.example.com",
			.value = "v=spf1 exp=mail.example.com -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "nonascii.example.com",
			.value = "v=spf1 exp=badexp.example.com -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "badexp.example.com",
			.value = "ï»¿Explanation"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "tworecs.example.com",
			.value = "v=spf1 exp=twoexp.example.com -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "twoexp.example.com",
			.value = "one"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "twoexp.example.com",
			.value = "two"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e23.example.com",
			.value = "v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"
		},
		/* not in testsuite: check that really exp= is given */
		{
			.type = DNSTYPE_TXT,
			.key = "no-exp.example.com",
			.value = "v=spf1 nexp=e11msg.example.com -all"
		},
		/* not in testsuite: check replacement of ASCII control-chars */
		{
			.type = DNSTYPE_TXT,
			.key = "control-exp-msg.example.com",
			.value = "message\nwith\rcontrol\tchars"
		},
		/* not in testsuite: check replacement of ASCII control-chars */
		{
			.type = DNSTYPE_TXT,
			.key = "control-exp.example.com",
			.value = "v=spf1 exp=control-exp-msg.example.com -all"
		},
		/* not in testsuite: check for valid modifier name */
		{
			.type = DNSTYPE_TXT,
			.key = "bad-mod1.example.com",
			.value = "v=spf1 _exp=e11msg.example.com -all"
		},
		/* not in testsuite: check for valid modifier name */
		{
			.type = DNSTYPE_TXT,
			.key = "bad-mod2.example.com",
			.value = "v=spf1 e?xp=e11msg.example.com -all"
		},
		/* not in testsuite: modifiers may not have qualification */
		{
			.type = DNSTYPE_TXT,
			.key = "bad-mod3.example.com",
			.value = "v=spf1 ~exp=e11msg.example.com -all"
		},
		/* not in testsuite: make sure redirect matches exactly */
		{
			.type = DNSTYPE_TXT,
			.key = "dont-come-here.example.com",
			.value = "+all"
		},
		/* not in testsuite: make sure redirect matches exactly */
		{
			.type = DNSTYPE_TXT,
			.key = "not-really-redirect.example.com", 
			.value = "v=spf1 redirectt=dont-come-here.example.com"
		},
		{
			.type = DNSTYPE_NONE
		}
	};
	const struct suite_testcase modtestcases[] = {
		{
			.name = "redirect-none",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e10.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "redirect-cancels-exp",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e1.example.com",
			.result = SPF_FAIL_PERM
		},
#if 0
		{
			.name = "redirect-syntax-error",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e17.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
#endif
		{
			.name = "include-ignores-exp",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e7.example.com",
			.exp = "Correct!",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "redirect-cancels-prior-exp",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e3.example.com",
			.exp = "See me.",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "invalid-modifier",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e5.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.name = "empty-modifier-name",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e6.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.name = "dorky-sentinel",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "Macro Error@e8.example.com",
			.exp = "Macro Error in implementation",
			.result = SPF_FAIL_PERM
		},
#if 0
		/* failing because multi-record detection does not work */
		{
			.name = "exp-multiple-txt",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e11.example.com",
			.result = SPF_FAIL_PERM
		},
#endif
		{
			.name = "exp-no-txt",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e22.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "exp-dns-error",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e21.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "exp-empty-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e12.example.com",
			.result = SPF_FAIL_PERM
		},
		{
			.name = "explanation-syntax-error",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e13.example.com",
			.result = SPF_FAIL_PERM
		},
#if 0
		{
			.name = "exp-syntax-error",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e16.example.com",
			.result = SPF_FAIL_PERM
		},
#endif
		{
			.name = "exp-twice",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e14.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.name = "redirect-empty-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e18.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.name = "redirect-twice",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e15.example.com",
			.result = SPF_FAIL_MALF
		},
		{
			.name = "unknown-modifier-syntax",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e9.example.com",
			.result = SPF_FAIL_PERM /* FIXME: should be SPF_FAIL_MALF */
		},
		{
			.name = "default-modifier-obsolete",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e19.example.com",
			.result = SPF_NEUTRAL
		},
		{
			.name = "default-modifier-obsolete2",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e20.example.com",
			.result = SPF_NEUTRAL
		},
		{
			.name = "non-ascii-exp",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foobar@nonascii.example.com",
			.result = SPF_FAIL_PERM
		},
#if 0
		/* failing because multi-record detection does not work */
		{
			.name = "two-exp-records",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foobar@tworecs.example.com",
			.result = SPF_FAIL_PERM
		},
#endif
		{
			.name = "exp-void",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e23.example.com",
			.result = SPF_FAIL_PERM
		},
		/* not in testsuite: check that really exp= is given */
		{
			.name = "no-exp-but-nexp",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@no-exp.example.com",
			.result = SPF_FAIL_PERM
		},
		/* not in testsuite: check replacement of ASCII control-chars */
		{
			.name = "exp-with-control-chars",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@control-exp.example.com",
			.exp = "message%with%control%chars",
			.result = SPF_FAIL_PERM
		},
		/* not in testsuite: check for valid modifier name */
		{
			.name = "modifier-bad-start",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@bad-mod1.example.com",
			.result = SPF_FAIL_MALF
		},
		/* not in testsuite: check for valid modifier name */
		{
			.name = "modifier-bad-intermediate",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@bad-mod2.example.com",
			.result = SPF_FAIL_MALF
		},
		/* not in testsuite: modifiers may not have qualification */
		{
			.name = "modifier-with-qualification",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@bad-mod3.example.com",
			.result = SPF_FAIL_MALF
		},
		/* not in testsuite: make sure redirect matches exactly */
		{
			.name = "not-really-redirect",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@not-really-redirect.example.com",
			.result = SPF_NEUTRAL
		},
		{
			.result = -1
		}
	};

	dnsdata = modentries;

	return run_suite_test(modtestcases);
}

static int
test_suite_include()
{
	/* INCLUDE mechanism syntax tests taken from SPF test suite 2009.10
	 * http://www.openspf.org/svn/project/test-suite/rfc4408-tests-2009.10.yml */
	const struct dnsentry includeentries[] = {
		{
			.type = DNSTYPE_A,
			.key = "mail.example.com",
			.value = "::ffff:1.2.3.4"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "ip5.example.com",
			.value = "v=spf1 ip4:1.2.3.5 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "ip6.example.com",
			.value = "v=spf1 ip4:1.2.3.6 ~all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "ip7.example.com",
			.value = "v=spf1 ip4:1.2.3.7 ?all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "erehwon.example.com",
			.value = "v=spfl am not an SPF record"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e1.example.com",
			.value = "v=spf1 include:ip5.example.com ~all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e2.example.com",
			.value = "v=spf1 include:ip6.example.com all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e3.example.com",
			.value = "v=spf1 include:ip7.example.com -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e4.example.com",
			.value = "v=spf1 include:ip8.example.com -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e5.example.com",
			.value = "v=spf1 include:e6.example.com -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e6.example.com",
			.value = "v=spf1 include +all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e7.example.com",
			.value = "v=spf1 include:erehwon.example.com -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e8.example.com",
			.value = "v=spf1 include: -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e9.example.com",
			.value = "v=spf1 include:ip5.example.com/24 -all"
		},
		{
			.type = DNSTYPE_TIMEOUT,
			.key = "ip8.example.com",
			.value = ""
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		},
	};
	const struct suite_testcase includetestcases[] = {
		{
			.name = "include-fail",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e1.example.com",
			.exp = NULL,
			.result = SPF_SOFTFAIL
		},
		{
			.name = "include-softfail",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e2.example.com",
			.exp = NULL,
			.result = SPF_PASS
		},
		{
			.name = "include-neutral",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e3.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "include-temperror",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e4.example.com",
			.exp = NULL,
			.result = SPF_TEMP_ERROR
		},
		{
			.name = "include-syntax-error",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e6.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "include-permerror",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e5.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "include-cidr",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e9.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "include-none",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e7.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "include-empty-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@e8.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.helo = NULL,
			.remoteip = NULL,
			.mailfrom = NULL,
			.exp = NULL,
			.result = -1
		}
	};

	dnsdata = includeentries;

	return run_suite_test(includetestcases);
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
			.type = DNSTYPE_TXT,
			.key = "exists-no-delimiter.example.net",
			.value = "v=spf1 exists -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "ip4-no-delimiter.example.net",
			.value = "v=spf1 ip4 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "ip6-no-delimiter.example.net",
			.value = "v=spf1 ip6 -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "redirect-no-delimiter.example.net",
			.value = "v=spf1 redirect -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "exp-no-delimiter.example.net",
			.value = "v=spf1 exp -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "a-end.example.net",
			.value = "v=spf1 a"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "a-colon-end.example.net",
			.value = "v=spf1 a:"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "exists-colon-end.example.net",
			.value = "v=spf1 exists:"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "marf-example-1.example.net",
			.value = "v=spf1 ra=postmaster -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "marf-example-2.example.net",
			.value = "v=spf1 mx:example.org ra=postmaster -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "marf-example-3.example.net",
			.value = "v=spf1 mx:example.org -all ra=postmaster rp=10 rr=e"
		},
		/* not in test suite: invalid makro letter */
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-redirect-makro3.example.net",
			.value = "v=spf1 redirect=foo.example.%qcom/"
		},
		/* not in test suite: exists with netmask given */
		{
			.type = DNSTYPE_TXT,
			.key = "invalid-exists-with-net4.example.net",
			.value = "v=spf1 exists:foo.example.com/16",
		},
		/* not in the test suite: exactly 9 terms causing DNS lookups */
		{
			.type = DNSTYPE_TXT,
			.key = "dns9.example.net",
			.value = "v=spf1 a a a a a a a a a"
		},
		/* not in the test suite: exactly 10 terms causing DNS lookups */
		{
			.type = DNSTYPE_TXT,
			.key = "dns10.example.net",
			.value = "v=spf1 a a a a a a a a a a +all"
		},
		/* not in the test suite: exactly 10 terms causing DNS lookups, using include */
		{
			.type = DNSTYPE_TXT,
			.key = "dns10i.example.net",
			.value = "v=spf1 include:dns9.example.net +all"
		},
		/* not in the test suite: exactly 10 terms causing DNS lookups, using redirect */
		{
			.type = DNSTYPE_TXT,
			.key = "dns10r.example.net",
			.value = "v=spf1 redirect=dns9.example.net"
		},
		/* not in the test suite: exactly 11 terms causing DNS lookups, using include */
		{
			.type = DNSTYPE_TXT,
			.key = "dns11i.example.net",
			.value = "v=spf1 include:dns10.example.net +all"
		},
		/* not in the test suite: exactly 11 terms causing DNS lookups, using recirect */
		{
			.type = DNSTYPE_TXT,
			.key = "dns11r.example.net",
			.value = "v=spf1 redirect=dns10.example.net"
		},
		/* not in the test suite: exactly 11 terms causing DNS lookups, during a */
		{
			.type = DNSTYPE_TXT,
			.key = "dns11a.example.net",
			.value = "v=spf1 include:dns9.example.net a a"
		},
		/* RfC 7208, section 6.1: Any "redirect" modifier MUST be ignored if there
		 * is an "all" mechanism anywhere in the record. */
		/* not in the test suite: redirect+all */
		{
			.type = DNSTYPE_TXT,
			.key = "redirect-before-all.example.net",
			.value = "v=spf1 redirect=allpass.example.net -all"
		},
		/* not in the test suite: all+redirect */
		{
			.type = DNSTYPE_TXT,
			.key = "redirect-after-all.example.net",
			.value = "v=spf1 +all redirect=allfail.example.net"
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		}
	};
	static int spfresults[] = {
		SPF_FAIL_PERM,
		SPF_FAIL_MALF,
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
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_NEUTRAL,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_FAIL_PERM,
		SPF_FAIL_PERM,
		SPF_FAIL_PERM,
		SPF_FAIL_MALF,
		SPF_FAIL_MALF,
		SPF_NEUTRAL,
		SPF_PASS,
		SPF_PASS,
		SPF_NEUTRAL,
		SPF_FAIL_PERM,
		SPF_FAIL_PERM,
		SPF_FAIL_PERM,
		SPF_FAIL_PERM,
		SPF_PASS,
		SPF_NONE
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
		return ++err;
	memcpy(xmitstat.helostr.s, parseentries[0].key, strlen(parseentries[0].key));
	memcpy(&xmitstat.sremoteip, &sender_ip6, sizeof(sender_ip6));
	xmitstat.ipv4conn = 0;
	if (init_helo(myhelo) != 0) {
		free(xmitstat.helostr.s);
		return ++err;
	}
	if (newstr(&xmitstat.mailfrom, strlen(mailfrom)) != 0) {
		free(heloname.s);
		free(xmitstat.helostr.s);
		return ENOMEM;
	}
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
	err += (check_received(SPF_FAIL_MALF, 0) ? 1 : 0);

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
test_behavior()
{
	const struct dnsentry ptrentries[] = {
		{
			.type = DNSTYPE_A,
			.key = "e6.example.com",
			.value = "::ffff:1.2.3.8"
		},
		{
			.type = DNSTYPE_NAME,
			.key = "::ffff:1.2.3.7",
			.value = "e6.example.com"
		},
		{
			.type = DNSTYPE_A,
			.key = "e.example.com",
			.value = "::ffff:1.2.8.3"
		},
		{
			.type = DNSTYPE_NAME,
			.key = "::ffff:1.2.8.3",
			.value = "e.example.com"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "e6.example.com",
			.value = "v=spf1 ptr -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "invalid.example.com",
			.value = "v=spf1 ptr:..: -all"
		},
		{
			.type = DNSTYPE_A,
			.key = "f.example.com",
			.value = "::ffff:1.2.9.9"
		},
		{
			.type = DNSTYPE_NAME,
			.key = "::ffff:1.2.9.9",
			.value = "e.example.com;f.example.org;g.example.org;h.example.org;"
					"i.example.org;j.example.org;k.example.org;l.example.org;"
					"m.example.org;n.example.org;o.example.org;p.example.org"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "domainspec-nonalpha.example.com",
			.value = "v=spf1 include:foo.bar- -all"
		},
		{
			.type = DNSTYPE_TXT,
			.key = "exp.example.org",
			.value = "you should not see this."
		},
		{
			.type = DNSTYPE_TXT,
			.key = "withexp.example.org",
			.value = "v=spf1 ip4: exp=exp.example.org"
		},
		{
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		},
	};
	const struct suite_testcase ptrtestcases[] = {
		{
			.name = "ptr-no-validated-domains",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.7",
			.mailfrom = "foo@e6.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "ptr-no-reverse-lookup",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.3",
			.mailfrom = "foo@e6.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "ptr-short-validated-domain",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.8.3",
			.mailfrom = "foo@e6.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "ptr-invalid-domainspec",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.8.3",
			.mailfrom = "foo@invalid.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "ptr-many-names",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.9.9",
			.mailfrom = "foo@e6.example.com",
			.exp = NULL,
			.result = SPF_FAIL_PERM
		},
		{
			.name = "domainspec-nonalpha",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.9.9",
			.mailfrom = "foo@domainspec-nonalpha.example.com",
			.exp = NULL,
			.result = SPF_FAIL_MALF
		},
		{
			.name = "no-exp-on-parse error",
			.helo = "mail.example.com",
			.remoteip = "::ffff:1.2.3.4",
			.mailfrom = "foo@withexp.example.org",
			.result = SPF_FAIL_MALF
		},
		{
			.helo = NULL,
			.remoteip = NULL,
			.mailfrom = NULL,
			.exp = NULL,
			.result = -1
		}
	};

	dnsdata = ptrentries;

	return run_suite_test(ptrtestcases);
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
		return ++err;
	memcpy(xmitstat.helostr.s, strchr(mailfrom, '@') + 1, strlen(strchr(mailfrom, '@') + 1));
	memcpy(&xmitstat.sremoteip, &sender_ip6, sizeof(sender_ip6));
	xmitstat.ipv4conn = 0;
	if (init_helo(myhelo) != 0) {
		free(xmitstat.helostr.s);
		return ENOMEM;
	}
	if (newstr(&xmitstat.mailfrom, strlen(mailfrom)) != 0) {
		free(xmitstat.helostr.s);
		free(heloname.s);
		return ENOMEM;
	}
	memcpy(xmitstat.mailfrom.s, mailfrom, strlen(mailfrom));

	for (i = SPF_NONE; i <= SPF_HARD_ERROR; i++) {
		if (i == 6)	/* this was SPF_FAIL_NONEX */
			continue;
		memcpy(&xmitstat.sremoteip, &sender_ip6, sizeof(sender_ip6));
		xmitstat.ipv4conn = 0;
		xmitstat.spfmechanism = mechanism[(i * 2) % 5];
		err += check_received(i, 1);
		memcpy(&xmitstat.sremoteip, &sender_ip4, sizeof(sender_ip4));
		xmitstat.ipv4conn = 1;
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
	err += test_suite_ptr();
	err += test_suite_a();
	err += test_suite_exists();
	err += test_suite_include();
	err += test_suite_modifiers();
	err += test_suite_mx();

	return err;
}

int main(int argc, char **argv)
{
	testcase_setup_ask_dnsa(test_ask_dnsa);
	testcase_setup_ask_dnsaaaa(test_ask_dnsaaaa);
	testcase_setup_ask_dnsmx(test_ask_dnsmx);
	testcase_setup_ask_dnsname(test_ask_dnsname);

	if (argc != 2)
		return EINVAL;

	if (strcmp(argv[1], "redhat") == 0)
		return runtest(&spftest_redhat);
	else if (strcmp(argv[1], "sf-mail") == 0)
		return runtest(&spftest_sfmail);
	else if (strcmp(argv[1], "_parse_") == 0)
		return test_parse();
	else if (strcmp(argv[1], "_behavior_") == 0)
		return test_behavior();
	else if (strcmp(argv[1], "_received_") == 0)
		return test_received();
	else if (strcmp(argv[1], "_suite_") == 0)
		return test_suite();
	else {
		fprintf(stderr, "invalid argument: %s\n", argv[1]);
		return EINVAL;
	}
}
