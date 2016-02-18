#include <qsmtpd/userfilters.h>

#include <control.h>
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>
#include <qsmtpd/userfilters.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

struct xmitstat xmitstat;
unsigned int goodrcpt;
struct recip *thisrecip;
const char **globalconf;
int controldir_fd = AT_FDCWD;

extern int cb_wildcardns(const struct userconf *ds, const char **logmsg, enum config_domain *t);

long
getsettingglobal(const struct userconf *ds __attribute__ ((unused)), const char *a, enum config_domain *t)
{
	assert(strcmp(a, "block_wildcardns") == 0);
	*t = CONFIG_DOMAIN;
	return 1;
}

/* the strings from doc/wildcardns */
static const char *jokers[] = {
	"ph_::ffff:203.119.6.168",
	"wc_::ffff:54.243.76.18",
	"wc_::ffff:107.20.147.236",
	"wc_::ffff:50.19.216.23",
	"wc_::ffff:54.225.151.133",
	"wc_::ffff:54.225.183.92",
	"wc_::ffff:54.225.217.143",
	"wc_::ffff:107.20.147.236",
	"wc_::ffff:50.19.216.23",
	"wc_::ffff:54.225.151.133",
	"wc_::ffff:54.225.183.92",
	"wc_::ffff:54.225.217.143",
	"wc_::ffff:54.243.76.18",
	"wc_::ffff:54.225.183.92",
	"wc_::ffff:54.225.217.143",
	"wc_::ffff:54.243.76.18",
	"wc_::ffff:107.20.147.236",
	"wc_::ffff:50.19.216.23",
	"wc_::ffff:54.225.151.133",
	NULL
};

int
loadlistfd(int fd __attribute__ ((unused)), char ***buf, checkfunc cf)
{
	for (unsigned int i = 0; jokers[i] != NULL; i++)
		if (cf(jokers[i]) != 0) {
			fprintf(stderr, "checker rejected input line %s\n",
					jokers[i]);
			errno = EINVAL;
			return -1;
		}

	*buf = malloc(sizeof(jokers));
	if (*buf == NULL)
		exit(ENOMEM);

	memcpy(*buf, jokers, sizeof(jokers));

	return 0;
}

static void
addjokerips(const unsigned int first, const unsigned int last, struct in6_addr *i)
{
	for (unsigned int j = first; j <= last; j++) {
		const char *ipstr = strchr(jokers[j], '_');
		int r;

		assert(ipstr != NULL);
		ipstr++;

		r = inet_pton(AF_INET6, ipstr, i + j - first);
		assert(r > 0);
	}
}

int
main(void)
{
	const char *logmsg = NULL;
	enum config_domain t;
	struct userconf ds;
	int err = 0;
	struct in6_addr frommxip[sizeof(jokers) / sizeof(jokers[0])];
	struct ips frommx = {
		.addr = frommxip,
		.count = 1
	};
	const char expected_logmsg[] = "MX is wildcard NS entry";
	const char unrelated_from[] = "foo@example.com";

	memset(&ds, 0, sizeof(ds));
	ds.domaindirfd = -1;

	/* test without xmitstat.frommx, should just do nothing */
	int r = cb_wildcardns(&ds, &logmsg, &t);
	if (r != FILTER_PASSED) {
		fprintf(stderr, "cb_wildcardns() without frommx returned %i instead of %i (FILTER_PASSED)\n",
				r, FILTER_PASSED);
		err++;
	}

	xmitstat.frommx = &frommx;
	r = inet_pton(AF_INET6, "::ffff:192.168.42.3", frommxip);
	assert(r > 0);
	frommxip[1] = frommxip[0];
	/* test without mailfrom, should just pass */
	r = cb_wildcardns(&ds, &logmsg, &t);
	if (r != FILTER_PASSED) {
		fprintf(stderr, "cb_wildcardns() without mailfrom returned %i instead of %i (FILTER_PASSED)\n",
			r, FILTER_PASSED);
		err++;
	}

	/* test with an IP that is no wildcard NS and a valid from */
	xmitstat.mailfrom.s = (char *)unrelated_from;
	xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);

	r = cb_wildcardns(&ds, &logmsg, &t);
	if (r != FILTER_PASSED) {
		fprintf(stderr, "cb_wildcardns() with valid IP and from returned %i instead of %i (FILTER_PASSED)\n",
			r, FILTER_PASSED);
		err++;
	}

	for (unsigned int i = 0; jokers[i] != NULL; i++) {
		const char *ipstr = strchr(jokers[i], '_');
		const size_t tldlen = ipstr - jokers[i];
		char frombuf[32] = "foo@example.";

		assert(tldlen < sizeof(frombuf) - strlen(frombuf) - 1);

		addjokerips(i, i, frommxip);

		xmitstat.mailfrom.s = (char *)unrelated_from;
		xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);
		frommx.count = 1;

		r = cb_wildcardns(&ds, &logmsg, &t);
		if (r != FILTER_PASSED) {
			fprintf(stderr, "cb_wildcardns() with MX IP set to wildcard entry %u and unrelated from returned %i instead of %i (FILTER_PASSED)\n",
					i, r, FILTER_DENIED_UNSPECIFIC);
			err++;
		}

		strncat(frombuf, jokers[i], tldlen);

		xmitstat.mailfrom.s = frombuf;
		xmitstat.mailfrom.len = strlen(frombuf);

		r = cb_wildcardns(&ds, &logmsg, &t);
		if (r != FILTER_DENIED_UNSPECIFIC) {
			fprintf(stderr, "cb_wildcardns() with MX IP set to wildcard entry %u returned %i instead of %i (FILTER_DENIED_UNSPECIFIC)\n",
					i, r, FILTER_DENIED_UNSPECIFIC);
			err++;
		}

		if ((logmsg == NULL) || (strcmp(logmsg, expected_logmsg) != 0)) {
			fprintf(stderr, "cb_wildcardns() with MX IP set to wildcard entry %u set logmsg to '%s' instead of '%s'\n",
					i, logmsg, expected_logmsg);
			err++;
		}

		frommx.count = 2;

		r = cb_wildcardns(&ds, &logmsg, &t);
		if (r != FILTER_PASSED) {
			fprintf(stderr, "cb_wildcardns() with MX IP set to wildcard entry %u and one valid returned %i instead of %i (FILTER_PASSED)\n",
					i, r, FILTER_DENIED_UNSPECIFIC);
			err++;
		}
	}

	/* check "all of a kind": a bogus entry with all MX IPs for that TLS set,
	 * which is basically what you would get in reality */
	for (unsigned int i = 0; jokers[i] != NULL; i++) {
		const char *ipstr = strchr(jokers[i], '_');
		const size_t tldlen = ipstr - jokers[i];
		char frombuf[32] = "foo@example.";
		unsigned int j;

		for (j = i + 1; jokers[j] != NULL; j++)
			if (strncmp(jokers[j], jokers[i], tldlen + 1) != 0)
				break;

		addjokerips(i, j - 1, frommxip);
		frommx.count = j - i;
		strncat(frombuf, jokers[i], tldlen);

		xmitstat.mailfrom.s = frombuf;
		xmitstat.mailfrom.len = strlen(frombuf);

		r = cb_wildcardns(&ds, &logmsg, &t);
		if (r != FILTER_DENIED_UNSPECIFIC) {
			fprintf(stderr, "cb_wildcardns() with %u wilcard MX IPs (%u...%u) returned %i instead of %i (FILTER_DENIED_UNSPECIFIC)\n",
					frommx.count, i, j - 1, r, FILTER_DENIED_UNSPECIFIC);
			err++;
		}

		if ((logmsg == NULL) || (strcmp(logmsg, expected_logmsg) != 0)) {
			fprintf(stderr, "cb_wildcardns() with %u wilcard MX IPs (%u...%u) set logmsg to '%s' instead of '%s'\n",
					frommx.count, i, j - 1, logmsg, expected_logmsg);
			err++;
		}

		i = j - 1;
	}

	return err;
}
