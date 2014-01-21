#include <qsmtpd/userfilters.h>
#include <qsmtpd/userconf.h>
#include "test_io/testcase_io.h"

#include <qsmtpd/antispam.h>
#include "control.h"
#include "libowfatconn.h"
#include <qsmtpd/qsmtpd.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h> 

struct xmitstat xmitstat;
unsigned int goodrcpt;
struct recip *thisrecip;
const char **globalconf;

int
check_host(const char *domain __attribute__ ((unused)))
{
	return SPF_NONE;
}

int
dnstxt(char **a __attribute__ ((unused)), const char *b __attribute__ ((unused)))
{
	errno = ENOENT;
	return -1;
}


int
userconf_get_buffer(const struct userconf *ds, const char *key, char ***values, checkfunc cf, const int useglobal)
{
	int type;
	int fd;
	int r;

	if (useglobal)
		fd = getfileglobal(ds, key, &type);
	else
		fd = getfile(ds, key, &type);

	if (fd < 0) {
		if (errno == ENOENT)
			return CONFIG_NONE;
		else
			return -errno;
	}

	r = loadlistfd(fd, values, cf);
	if (r < 0)
		return -errno;

	if (*values == NULL)
		return CONFIG_NONE;

	assert((type >= CONFIG_USER) && (type <= CONFIG_GLOBAL));
	return type;
}

static void
default_session_config(void)
{
	xmitstat.esmtp = 0; /* no */
	xmitstat.ipv4conn = 1; /* yes */
	xmitstat.check2822 = 2; /* no decision yet */
	xmitstat.helostatus = 1; /* HELO is my name */
	xmitstat.spf = SPF_NONE;
	xmitstat.fromdomain = 3; /* permanent error */
	xmitstat.spacebug = 1; /* yes */
	xmitstat.mailfrom.s = "user@invalid";
	xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);
	xmitstat.helostr.s = "my.host.example.org";
	xmitstat.helostr.len = strlen(xmitstat.helostr.s);
	strncpy(xmitstat.remoteip, "::ffff:192.168.8.9", sizeof(xmitstat.remoteip) - 1);

	TAILQ_INIT(&head);
}

static inline int __attribute__ ((nonnull (1,2)))
str_starts_with(const char *str, const char *pattern)
{
	return (strncmp(str, pattern, strlen(pattern)) == 0);
}

/*
 * The message in the control file (expect) has spaces replaced by underscores
 * because the configuration file loader doesn't allow spaces in values.
 */
static int __attribute__ ((nonnull (1,2)))
errormsg_matches(const char *msg, const char *expect)
{
	size_t pos = 0;

	while (msg[pos] != '\0') {
		if ((msg[pos] == expect[pos]) ||
				((msg[pos] == ' ') && (expect[pos] == '_'))) {
			pos++;
			continue;
		}
		return 0;
	}

	return (expect[pos] == '\0');
}

static unsigned int log_count;

void
test_log_writen(int priority, const char **s)
{
	int i;

	printf("log priority %i: ", priority);
	for (i = 0; s[i] != NULL; i++)
		printf("%s", s[i]);

	printf("\n");

	log_count++;
}

int
main(void)
{
	int i;
	int err = 0;
	struct userconf uc;
	struct recip dummyrecip;
	struct recip firstrecip;
	int basedirfd;
	char confpath[PATH_MAX];

	STREMPTY(uc.domainpath);
	STREMPTY(uc.userpath);
	uc.userconf = NULL;
	uc.domainconf = NULL;
	globalconf = NULL;
	memset(&xmitstat, 0, sizeof(xmitstat));

	TAILQ_INIT(&head);

	thisrecip = &dummyrecip;
	dummyrecip.to.s = "postmaster";
	dummyrecip.to.len = strlen(dummyrecip.to.s);
	dummyrecip.ok = 0;
	TAILQ_INSERT_TAIL(&head, &dummyrecip, entries);

	xmitstat.spf = SPF_IGNORE;

	for (i = 0; rcpt_cbs[i] != NULL; i++) {
		const char *errmsg;
		int bt = 0;
		int r = rcpt_cbs[i](&uc, &errmsg, &bt);

		if (r != 0) {
			fprintf(stderr, "filter %i returned %i\n", i, r);
			err++;
		}
	}

	/* Now change some global state to get better coverage. But the
	 * result may not change, the mail may still not be blocked. */
	default_session_config();
	xmitstat.esmtp = 1; /* yes */

	thisrecip = &dummyrecip;
	firstrecip.to.s = "baz@example.com";
	firstrecip.to.len = strlen(firstrecip.to.s);
	firstrecip.ok = 0;
	TAILQ_INSERT_TAIL(&head, &firstrecip, entries);
	TAILQ_INSERT_TAIL(&head, &dummyrecip, entries);

	for (i = 0; rcpt_cbs[i] != NULL; i++) {
		const char *errmsg;
		int bt = 0;
		int r = rcpt_cbs[i](&uc, &errmsg, &bt);

		if (r != 0) {
			fprintf(stderr, "filter %i returned %i\n", i, r);
			err++;
		}
	}

	i = 0;
	strncpy(confpath, "0/", sizeof(confpath));
	basedirfd = open(confpath, O_RDONLY);

	testcase_setup_log_writen(test_log_writen);
	testcase_ignore_ask_dnsa();

	while (basedirfd >= 0) {
		char userpath[PATH_MAX];
		int j;
		char **b = NULL;	/* test configuration storage */
		const char *failmsg = NULL;	/* expected failure message */
		int r = 0;			/* filter result */
		const char *fmsg = NULL;	/* returned failure message */
		unsigned int exp_log_count = 0;	/* expected log messages */

		close(basedirfd);

		/* set default configuration */
		default_session_config();

		log_count = 0;

		thisrecip = &dummyrecip;
		firstrecip.to.s = "baz@example.com";
		firstrecip.to.len = strlen(firstrecip.to.s);
		firstrecip.ok = 0;
		TAILQ_INSERT_TAIL(&head, &firstrecip, entries);
		TAILQ_INSERT_TAIL(&head, &dummyrecip, entries);

		snprintf(userpath, sizeof(userpath), "%i/session", i);
		j = open(userpath, O_RDONLY);
		if (j >= 0) {
			if (loadlistfd(j, &b, NULL)) {
				fprintf(stderr, "cannot open %s\n", userpath);
				return 1;
			}

			if (b != NULL) {
				int k;

				for (k = 0; b[k] != NULL; k++) {
					if (str_starts_with(b[k], "mailfrom:")) {
						xmitstat.mailfrom.s = b[k] + strlen("mailfrom:");
						xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);
					} else if (strcmp(b[k], "esmtp") == 0) {
						xmitstat.esmtp = 1;
					} else if (strcmp(b[k], "ip:") == 0) {
						strncpy(xmitstat.remoteip, b[k] + strlen("ip:"),
								sizeof(xmitstat.remoteip) - 1);
					} else if (str_starts_with(b[k], "failmsg:")) {
						failmsg = b[k] + strlen("failmsg:");
					} else if (str_starts_with(b[k], "logmsg:")) {
						char *endptr;
						exp_log_count = strtoul(b[k] + strlen("logmsg:"),
								&endptr, 10);
						if (*endptr != '\0') {
							fprintf(stderr, "parse error in %s line %i: %s\n",
									userpath, k, b[k]);
							free(b);
							return 1;
						}
					}
				}
			}
		}

		if (inet_pton(AF_INET6, xmitstat.remoteip, &xmitstat.sremoteip) <= 0) {
			fprintf(stderr, "bad ip address given: %s\n", xmitstat.remoteip);
			free(b);
			return 1;
		}
		xmitstat.ipv4conn = IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip) ? 1 : 0;

		snprintf(userpath, sizeof(userpath), "%i/user/", i);
		basedirfd = open(userpath, O_RDONLY);
		if (basedirfd < 0) {
			uc.userpath.s = NULL;
			uc.userpath.len = 0;
		} else {
			close(basedirfd);
			uc.userpath.s = userpath;
			uc.userpath.len = strlen(uc.userpath.s);
		}

		snprintf(confpath, sizeof(confpath), "%i/domain/", i);
		basedirfd = open(confpath, O_RDONLY);
		if (basedirfd < 0) {
			uc.domainpath.s = NULL;
			uc.domainpath.len = 0;
		} else {
			close(basedirfd);
			uc.domainpath.s = confpath;
			uc.domainpath.len = strlen(uc.domainpath.s);
		}

		printf("testing configuration %i,%s%s\n", i,
				uc.userpath.len ? " user" : "",
				uc.domainpath.len ? " domain" : "");

		for (j = 0; (rcpt_cbs[j] != NULL) && (r == 0); j++) {
			int bt = 0;
			fmsg = NULL;
			r = rcpt_cbs[j](&uc, &fmsg, &bt);
		}

		if ((r != 0) && (failmsg == NULL)) {
			fprintf(stderr, "configuration %i: filter %i returned %i, message %s\n",
					i, j, r, fmsg);
			err++;
		} else if ((r == 0) && (failmsg != NULL)) {
			fprintf(stderr, "configuration %i: no filter matched, but error should have been '%s'\n",
					i, failmsg);
			err++;
		} else if (failmsg != NULL) {
			if (fmsg == NULL) {
				fprintf(stderr, "configuration %i: filter %i matched with code %i, but the expected message '%s' was not set\n",
						i, j, r, failmsg);
				err++;
			} else if (!errormsg_matches(fmsg, failmsg)) {
				fprintf(stderr, "configuration %i: filter %i matched with code %i, but the expected message '%s' was not set, but '%s'\n",
						i, j, r, failmsg, fmsg);
				err++;
			}
		}

		if (log_count != exp_log_count) {
			fprintf(stderr, "configuration %i: expected %u log messages, got %u\n",
					i, exp_log_count, log_count);
			err++;
		}

		i++;
		snprintf(confpath, sizeof(confpath), "%i/", i);
		basedirfd = open(confpath, O_RDONLY);
		free(b);
	}

	return err;
}
