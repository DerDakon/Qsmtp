#include "userfilters.h"
#include "test_io/testcase_io.h"

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

extern int cb_badcc(const struct userconf *ds, char **logmsg, int *t);

static struct recip recips[] = {
	{
		.to = {
			.s = "foo@example.com"
		}
	},
	{
		.to = {
			.s = "bar@example.com"
		}
	},
	{
		.to = { 
			.s = "foo@example.net"
		}
	},
	{
		.to = {
			.s = "bar@example.net"
		}
	}
};

#define RCPT_PATTERNS 4

static struct userconf ds;

static void
setup_userconf()
{
	if (strstr(thisrecip->to.s, "@example.net") != NULL) {
		ds.domainpath.s = "example.net/";
		if (strcmp(thisrecip->to.s, "foo@example.net")) {
			ds.userpath.s = "example.net/foo/";
		} else {
			ds.userpath.s = NULL;
		}
	} else {
		ds.domainpath.s = NULL;
		ds.userpath.s = NULL;
	}

	if (ds.domainpath.s == NULL)
		ds.domainpath.len = 0;
	else
		ds.domainpath.len = strlen(ds.domainpath.s);
	if (ds.userpath.s == NULL)
		ds.userpath.len = 0;
	else
		ds.userpath.len = strlen(ds.userpath.s);
}

static void
setup_recip_order(unsigned int valid, int r0, int r1, int r2, int r3)
{
	/* it's easier to pass them as single values from outside
	 * since this is only a testcase I go this way */
	int rflags[RCPT_PATTERNS] = { r0, r1, r2, r3 };
	int i;

	assert(r0 >= 0);
	assert(r0 < RCPT_PATTERNS);
	assert(r1 < RCPT_PATTERNS);
	assert(r2 < RCPT_PATTERNS);
	assert(r3 < RCPT_PATTERNS);
	assert(valid < (1 << RCPT_PATTERNS));

	i = 0;
	goodrcpt = 0;
	TAILQ_INIT(&head);

	for (i = 0; (i < RCPT_PATTERNS) && (rflags[i] >= 0); i++) {
		thisrecip = &recips[rflags[i]];
		thisrecip->ok = (valid & (1 << rflags[i]));
		memset(&thisrecip->entries, 0, sizeof(thisrecip->entries));
		TAILQ_INSERT_TAIL(&head, thisrecip, entries);
		if (thisrecip->ok)
			goodrcpt++;
	}

	setup_userconf();
}

int main(int argc, char **argv)
{
	char *logmsg;
	int t;
	int r;
	int err = 0;

	testcase_ignore_log_write();
	testcase_ignore_log_writen();

	if (argc != 2) {
		fprintf(stderr, "usage: %s base_directory\n", argv[0]);
		return EFAULT;
	}

	if (chdir(argv[1]) != 0) {
		fprintf(stderr, "error: cannot chdir() to %s\n", argv[1]);
		return EFAULT;
	}

	memset(&ds, 0, sizeof(ds));
	globalconf = NULL;
	for (r = 0; r < RCPT_PATTERNS; r++)
		recips[r].to.len = strlen(recips[r].to.s);

	setup_recip_order(1, 0, -1, -1, -1);

	r = cb_badcc(&ds, &logmsg, &t);
	if (r != 0) {
		fprintf(stderr, "with only a single recipient no errors should happen,"
				" but result is %i\n", r);
		err++;
	}

	setup_recip_order(3, 0, 1, -1, -1);
	r = cb_badcc(&ds, &logmsg, &t);
	if (r != 0) {
		fprintf(stderr, "for recipients without config no errors should happen,"
				" but result is %i\n", r);
		err++;
	}

	setup_recip_order(5, 0, 2, -1, -1);
	r = cb_badcc(&ds, &logmsg, &t);
	if (r != 2) {
		fprintf(stderr, "foo@example.net should reject bad CC, but result is %i\n", r);
		err++;
	}

	setup_recip_order(4, 2, 0, -1, -1);
	thisrecip = &recips[2];
	setup_userconf();
	t = -1;
	r = cb_badcc(&ds, &logmsg, &t);
	if (r != 2) {
		fprintf(stderr, "foo@example.net as first recipient with example.net following"
				"should reject, but result is %i, t = %i\n", r, t);
		err++;
	} else if (t != 1) {
		fprintf(stderr, "foo@example.net should reject with user policy,"
				" but t is %i\n", t);
		err++;
	}

	setup_recip_order(8, 0, 3, -1, -1);
	t = -1;
	r = cb_badcc(&ds, &logmsg, &t);
	if (r != 2) {
		fprintf(stderr, "bar@example.net should reject foo@example.com,"
				"but result is %i, t = %i\n", r, t);
		err++;
	} else if (t != 0) {
		fprintf(stderr, "bar@example.net should reject with domain policy,"
				" but t is %i\n", t);
		err++;
	}

	return err;
}
