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
	"ac_::ffff:81.6.204.23",
	"mp_::ffff:66.135.225.102",
	"museum_::ffff:195.7.77.20",
	"nu_::ffff:212.181.91.6",
	"nu_::ffff:69.25.75.72",
	"nu_::212.181.91.6",
	"nu_::69.25.75.72",
	"ph_::ffff:203.119.4.6",
	"tk_::ffff:195.20.32.77",
	"tk_::ffff:195.20.32.78",
	"sh_::ffff:81.6.204.23",
	"tm_::ffff:81.6.204.23",
	"ws_::ffff:216.35.187.246",
	NULL
};

int
loadlistfd(int fd __attribute__ ((unused)), char ***buf, checkfunc cf __attribute__ ((unused)))
{
	*buf = malloc(sizeof(jokers));
	if (*buf == NULL)
		exit(ENOMEM);

	memcpy(*buf, jokers, sizeof(jokers));

	return 0;
}

int
main(void)
{
	const char *logmsg;
	enum config_domain t;
	struct userconf ds;
	int r;
	int err = 0;
	struct in6_addr frommxip;
	struct ips frommx = {
		.addr = &frommxip,
		.count = 1
	};

	memset(&ds, 0, sizeof(ds));
	ds.domaindirfd = -1;

	/* test without xmitstat.frommx, should just do nothing */
	r = cb_wildcardns(&ds, &logmsg, &t);
	if (r != FILTER_PASSED) {
		fprintf(stderr, "cb_wildcardns() without frommx returned %i instead of %i (FILTER_PASSED)\n",
				r, FILTER_PASSED);
		err++;
	}

	xmitstat.frommx = &frommx;
	/* test without mailfrom, should also just do nothing */
	r = cb_wildcardns(&ds, &logmsg, &t);
	if (r != FILTER_PASSED) {
		fprintf(stderr, "cb_wildcardns() without mailfrom returned %i instead of %i (FILTER_PASSED)\n",
			r, FILTER_PASSED);
		err++;
	}

	/* test with an IP that is no wildcard NS and a valid from */
	r = inet_pton(AF_INET6, "::ffff:192.168.42.3", &frommxip);
	assert(r > 0);
	xmitstat.mailfrom.s = "foo@example.com";
	xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);

	r = cb_wildcardns(&ds, &logmsg, &t);
	if (r != FILTER_PASSED) {
		fprintf(stderr, "cb_wildcardns() with valid IP and from returned %i instead of %i (FILTER_PASSED)\n",
			r, FILTER_PASSED);
		err++;
	}

	return err;
}
