#include "userfilters.h"
#include "test_io/testcase_io.h"

#include "antispam.h"
#include "libowfatconn.h"
#include "qsmtpd.h"

#include <assert.h>
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
main(void)
{
	int i;
	int err = 0;
	struct userconf uc;
	struct recip dummyrecip;

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

	for (i = 0; rcpt_cbs[i] != NULL; i++) {
		const char *errmsg;
		int bt = 0;
		int r = rcpt_cbs[i](&uc, &errmsg, &bt);

		if (r != 0) {
			fprintf(stderr, "filter %i returned %i\n", i, r);
			err++;
		}
	}

	return err;
}
