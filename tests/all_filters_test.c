#include "userfilters.h"
#include "test_io/testcase_io.h"

#include "antispam.h"
#include "control.h"
#include "libowfatconn.h"
#include "qsmtpd.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

int
main(int argc, char **argv)
{
	int i;
	int err = 0;
	struct userconf uc;
	struct recip dummyrecip;
	struct recip firstrecip;
	DIR *basedir;
	char confpath[PATH_MAX];

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <basedir>\n", argv[0]);
		return EINVAL;
	}

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
	snprintf(confpath, sizeof(confpath), "%s/0/", argv[1]);
	basedir = opendir(confpath);

	while (basedir != NULL) {
		char userpath[PATH_MAX];
		int j;
		char *a = NULL, **b = NULL;	/* test configuration storage */
		const char *failmsg = NULL;	/* expected failure message */
		int r = 0;			/* filter result */
		const char *fmsg = NULL;	/* returned failure message */

		closedir(basedir);

		/* set default configuration */
		default_session_config();

		thisrecip = &dummyrecip;
		firstrecip.to.s = "baz@example.com";
		firstrecip.to.len = strlen(firstrecip.to.s);
		firstrecip.ok = 0;
		TAILQ_INSERT_TAIL(&head, &firstrecip, entries);
		TAILQ_INSERT_TAIL(&head, &dummyrecip, entries);

		snprintf(userpath, sizeof(userpath), "%s/%i/session", argv[1], i);
		j = open(userpath, O_RDONLY);
		if (j >= 0) {
			int k;

			if (loadlistfd(j, &a, &b, NULL)) {
				fprintf(stderr, "cannot open %s\n", userpath);
				return 1;
			}

			if (a == NULL) {
				assert(b == NULL);
			} else {
				assert(b != NULL);

				for (k = 0; b[k] != NULL; k++) {
					if (str_starts_with(b[k], "mailfrom:")) {
						xmitstat.mailfrom.s = b[k] + strlen("mailfrom:");
						xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);
					} else if (strcmp(b[k], "esmtp") == 0) {
						xmitstat.esmtp = 1;
					} else if (strcmp(b[k], "ipv6") == 0) {
						xmitstat.ipv4conn = 0;
					} else if (str_starts_with(b[k], "failmsg:")) {
						failmsg = b[k] + strlen("failmsg:");
					} else if (*b[k] != '#') {
						fprintf(stderr, "unexpected line in %s: %s\n", userpath, b[k]);
						free(a);
						free(b);
						return 1;
					}
				}
			}
		}

		snprintf(userpath, sizeof(userpath), "%s/%i/user/", argv[1], i);
		basedir = opendir(userpath);
		if (basedir == NULL) {
			uc.userpath.s = NULL;
			uc.userpath.len = 0;
		} else {
			closedir(basedir);
			uc.userpath.s = userpath;
			uc.userpath.len = strlen(uc.userpath.s);
		}

		snprintf(confpath, sizeof(confpath), "%s/%i/domain/", argv[1], i);
		basedir = opendir(confpath);
		if (basedir == NULL) {
			uc.domainpath.s = NULL;
			uc.domainpath.len = 0;
		} else {
			closedir(basedir);
			uc.domainpath.s = confpath;
			uc.domainpath.len = strlen(uc.domainpath.s);
		}

		printf("testing configuration %i,%s%s\n", i,
				uc.userpath.len ? " user" : "",
				uc.domainpath.len ? " domain" : "");

		for (j = 0; (rcpt_cbs[j] != NULL) && (r == 0); j++) {
			int bt = 0;
			r = rcpt_cbs[j](&uc, &fmsg, &bt);
		}

		if ((r != 0) && (failmsg == NULL)) {
			fprintf(stderr, "filter %i returned %i, message %s\n", j, r, fmsg);
			err++;
		} else if ((r == 0) && (failmsg != NULL)) {
			fprintf(stderr, "no filter matched, but error should have been '%s'\n", failmsg);
			err++;
		} else if (failmsg != NULL) {
			if (fmsg == NULL) {
				fprintf(stderr, "filter %i matched, but the expected message '%s' was not set\n",
						j, failmsg);
				err++;
			} else if (!errormsg_matches(fmsg, failmsg)) {
				fprintf(stderr, "filter %i matched, but the expected message '%s' was not set, but '%s'\n",
						j, failmsg, fmsg);
				err++;
			}
		}

		i++;
		snprintf(confpath, sizeof(confpath), "%s/%i/", argv[1], i);
		basedir = opendir(confpath);
		free(a);
		free(b);
	}

	return err;
}
