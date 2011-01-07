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

static struct spftestcase spftest_redhat = {
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

	if (strstr(buf, "  ") != NULL) {
		fputs("spfreceived() has written duplicate whitespace\n", stderr);
		return 1;
	}

	tmp = skipwhitespace(buf + strlen(hdrline) + strlen(spfstates[r]),
			strlen(buf) - strlen(hdrline) - strlen(spfstates[r]));
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

static int
runtest(struct spftestcase *tc)
{
	int err = 0;

	memset(&xmitstat, 0, sizeof(xmitstat));

	if (newstr(&xmitstat.mailfrom, strlen(tc->from)))
		return ENOMEM;

	if (newstr(&heloname, strlen(tc->helo)))
		return ENOMEM;

	memcpy(xmitstat.mailfrom.s, tc->from, strlen(tc->from));
	memcpy(heloname.s, tc->helo, strlen(tc->helo));

	dnsdata = tc->dns;

	strncpy(xmitstat.remoteip, tc->goodip, sizeof(xmitstat.remoteip));
	inet_pton(AF_INET6, tc->goodip, &xmitstat.sremoteip);

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

	while (ip4invalid[i] != NULL) {
		ip4entries[0].value = ip4invalid[i];

		if (check_host(ip4entries[0].key) != SPF_HARD_ERROR) {
			fprintf(stderr, "check_host() did not reject invalid IPv4 entry '%s'\n", ip4invalid[i]);
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

		if (check_host(ip6entries[0].key) != SPF_HARD_ERROR) {
			fprintf(stderr, "check_host() did not reject invalid IPv6 entry '%s'\n", ip6invalid[i]);
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
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		}
	};
	const char *mxinvalid[] = {
		"v=spf1 mx//",
		"v=spf1 mx/a/12",
		"v=spf1 mx/12/12",
		"v=spf1 mx/34",
		"v=spf1 mx//140",
		"v=spf1 mx///64",
		"v=spf1 mx/0",
		NULL
	};
	const char *mxvalid[] = {
		"v=spf1 mx//12 -all",
		"v=spf1 mx/12//64 -all",
		"v=spf1 mx -all",
		NULL
	};
	const char *mxvalid_reject[] = {
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

		if (check_host(mxentries[0].key) != SPF_HARD_ERROR) {
			fprintf(stderr, "check_host() did not reject invalid MX entry '%s'\n", mxinvalid[i]);
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

		i++;
	}

	return err;
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
			.type = DNSTYPE_NONE,
			.key = NULL,
			.value = NULL
		}
	};
	static int spfresults[] = {
		SPF_HARD_ERROR,
		SPF_FAIL_NONEX,
		SPF_NONE,
		SPF_HARD_ERROR,
		SPF_NEUTRAL,
		SPF_NEUTRAL,
		SPF_FAIL_PERM,
		SPF_SOFTFAIL,
		SPF_PASS,
		SPF_PASS,
		SPF_HARD_ERROR,
		SPF_SOFTFAIL
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
		err += check_received(i, 1);
		memcpy(&xmitstat.sremoteip, &sender_ip4, sizeof(sender_ip4));
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

