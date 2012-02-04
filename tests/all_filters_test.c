#include "userfilters.h"
#include "test_io/testcase_io.h"

#include "antispam.h"
#include "libowfatconn.h"
#include "qsmtpd.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>

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
	xmitstat.esmtp = 1; /* yes */
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

	xmitstat.esmtp = 0; /* no */

	i = 0;
	snprintf(confpath, sizeof(confpath), "%s/0/", argv[1]);
	basedir = opendir(confpath);

	while (basedir != NULL) {
		char userpath[PATH_MAX];
		int j;

		closedir(basedir);
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

		for (j = 0; rcpt_cbs[j] != NULL; j++) {
			const char *errmsg;
			int bt = 0;
			int r = rcpt_cbs[j](&uc, &errmsg, &bt);

			if (r != 0) {
				fprintf(stderr, "filter %i returned %i\n", j, r);
				err++;
			}
		}

		i++;
		snprintf(confpath, sizeof(confpath), "%s/%i/", argv[1], i);
		basedir = opendir(confpath);
	}

	return err;
}
