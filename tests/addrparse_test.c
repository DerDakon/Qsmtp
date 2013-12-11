#include <qsmtpd/addrparse.h>
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>
#include <qsmtpd/vpop.h>
#include <netio.h>
#include <sstring.h>
#include "test_io/testcase_io.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>

static struct {
	char inpattern[128];	/* the input pattern to addrparse() */
	int flags;		/* the flags parameter to pass to addrparse() */
	const int syntaxresult;	/* the desired result of addrsyntax() */
	int expect_netwrite;	/* if call to netwrite() is expected */
	int expect_net_writen;	/* if call to netwrite() is expected */
	const int parseresult;	/* expected result of addrparse() */
	int expect_tarpit;	/* how often tarpit() is expected to be called */
	int vgetdir_result;	/* result to return from vget_dir() */
	int userexists_result;	/* result to return from user_exists() */
} testdata[] = {
	{
		.inpattern = "missing@end.bracket",
		.flags = 0,
		.syntaxresult = 0,
		.expect_netwrite = 1,
		.parseresult = EBOGUS,
		.expect_tarpit = 1,
		.vgetdir_result = 0,
	},
	{
		.inpattern = "missing@end.bracket",
		.flags = 0,
		.syntaxresult = -ENOMEM,
		.expect_netwrite = 0,
		.parseresult = ENOMEM,
		.expect_tarpit = 0,
		.vgetdir_result = 0,
	},
	{
		.inpattern = "postmaster>",
		.flags = 1,
		.syntaxresult = 1,
		.expect_netwrite = 0,
		.parseresult = 0,
		.expect_tarpit = 0,
		.vgetdir_result = 0,
	},
	/* domain not in rcpthosts */
	{
		.inpattern = "user@example.com>",
		.flags = 1,
		.syntaxresult = 3,
		.expect_netwrite = 0,
		.parseresult = -2,
		.expect_tarpit = 0,
		.vgetdir_result = 0,
	},
	/* domain in rcpthosts, but not local */
	{
		.inpattern = "user@example.net>",
		.flags = 1,
		.syntaxresult = 3,
		.expect_netwrite = 0,
		.parseresult = 0,
		.expect_tarpit = 0,
		.vgetdir_result = 0,
	},
	/* local domain, but user does not exist */
	{
		.inpattern = "user@local.example.net>",
		.flags = 1,
		.syntaxresult = 3,
		.expect_netwrite = 0,
		.expect_net_writen = 1,
		.parseresult = -1,
		.expect_tarpit = 1,
		.vgetdir_result = 1,
		.userexists_result = 0,
	},
	/* existing local user */
	{
		.inpattern = "existing@local.example.net>",
		.flags = 1,
		.syntaxresult = 3,
		.expect_netwrite = 0,
		.expect_net_writen = 0,
		.parseresult = 0,
		.expect_tarpit = 0,
		.vgetdir_result = 1,
		.userexists_result = 1,
	},
	/* existing local user, addressed with IP address */
	{
		.inpattern = "existing@[192.0.2.4]>",
		.flags = 1,
		.syntaxresult = 4,
		.expect_netwrite = 0,
		.expect_net_writen = 0,
		.parseresult = 0,
		.expect_tarpit = 0,
		.vgetdir_result = 1,
		.userexists_result = 1,
	},
	/* existing local user, but wrong IP address */
	{
		.inpattern = "existing@[192.0.2.42]>",
		.flags = 1,
		.syntaxresult = 4,
		.expect_netwrite = 0,
		.expect_net_writen = 1,
		.parseresult = -1,
		.expect_tarpit = 1,
	},
	/* local domain, but no /var/qmail/users/cdb file */
	{
		.inpattern = "existing@local.example.net>",
		.flags = 1,
		.syntaxresult = 3,
		.expect_netwrite = 0,
		.expect_net_writen = 0,
		.parseresult = 0,
		.expect_tarpit = 0,
		.vgetdir_result = -ENOENT,
	},
	/* existing local user, but vget_dir() returns with error */
	{
		.inpattern = "existing@local.example.net>",
		.flags = 1,
		.syntaxresult = 3,
		.expect_netwrite = 0,
		.expect_net_writen = 0,
		.parseresult = ENOMEM,
		.expect_tarpit = 0,
		.vgetdir_result = -ENOMEM,
	},
	/* existing local user, but user_exists() returns with error */
	{
		.inpattern = "existing@local.example.net>",
		.flags = 1,
		.syntaxresult = 3,
		.expect_netwrite = 0,
		.expect_net_writen = 0,
		.parseresult = ENOMEM,
		.expect_tarpit = 0,
		.vgetdir_result = 1,
		.userexists_result = -ENOMEM
	},
	{
		.inpattern = ""
	}
};

struct xmitstat xmitstat;
static unsigned int testindex;
static int errcounter;
string liphost;
char domaindirbuffer[256];

void
tarpit(void)
{
	if (testdata[testindex].expect_tarpit == 0) {
		fprintf(stderr, "unexpected call to tarpit() for index %u\n", testindex);
		errcounter++;
		return;
	}

	testdata[testindex].expect_tarpit--;
}

void
userconf_init(struct userconf *ds)
{
	STREMPTY(ds->domainpath);
	STREMPTY(ds->userpath);
	ds->userconf = NULL;
	ds->domainconf = NULL;
}

void
userconf_free(struct userconf *ds)
{
	assert((ds->domainpath.s == NULL) || (ds->domainpath.s == domaindirbuffer));
	free(ds->userpath.s);
	free(ds->userconf);
	free(ds->domainconf);

	userconf_init(ds);
}

int
addrsyntax(char *in, const int flags, string *addr, char **more)
{
	char *bracket;

	assert(more != NULL);

	if (flags != testdata[testindex].flags) {
		fprintf(stderr, "index %u: expected flags %i but got %i\n",
				testindex, testdata[testindex].flags, flags);
		errcounter++;
	}

	if (testdata[testindex].syntaxresult < 0) {
		errno = -testdata[testindex].syntaxresult;
		return -1;
	} else if (testdata[testindex].syntaxresult == 0) {
		return 0;
	}

	bracket = strchr(in, '>');

	if (newstr(addr, bracket - in + 1)) {
		fprintf(stderr, "index %u: out of memory allocating %zu byte for addr\n",
				testindex, bracket - in + 1);
		exit(ENOMEM);
	}

	memcpy(addr->s, in, --addr->len);
	addr->s[addr->len] = '\0';

	return testdata[testindex].syntaxresult;
}

static const char pathstart[] = "testdirbase/";

int
vget_dir(const char *domain, string *domaindir)
{
	snprintf(domaindirbuffer, sizeof(domaindirbuffer), "%s%s", pathstart, domain);
	domaindir->s = domaindirbuffer;
	domaindir->len = strlen(domaindir->s);

	return testdata[testindex].vgetdir_result;
}

int
user_exists(const string *localpart, struct userconf *ds)
{
	assert(strncmp(ds->userpath.s, pathstart, strlen(pathstart)) == 0);
	assert(strncmp(ds->domainpath.s, pathstart, strlen(pathstart)) == 0);
	assert(strncmp(testdata[testindex].inpattern, localpart->s, localpart->len) == 0);

	if (testdata[testindex].userexists_result < 0) {
		errno = -testdata[testindex].userexists_result;
		return -1;
	} else {
		return testdata[testindex].userexists_result;
	}
}

int
test_netnwrite(const char *s, const size_t l)
{
	const char expstr[] = "501 5.1.3 domain of mail address is syntactically incorrect\r\n";

	if (l != strlen(expstr)) {
		fprintf(stderr, "index %u: length of input '%s' did not match expected length\n",
				testindex, s);
		errcounter++;
		return -ECONNRESET;
	}

	if (strcmp(s, expstr) != 0) {
		fprintf(stderr, "index %u: input '%s' did not match expected input\n",
				testindex, s);
		errcounter++;
		return -ECONNRESET;
	}

	if (testdata[testindex].expect_netwrite == 0) {
		fprintf(stderr, "index %u: unexpected call to netwrite()\n",
				testindex);
		errcounter++;
		return -ECONNRESET;
	}

	testdata[testindex].expect_netwrite--;

	return 0;
}

int
test_net_writen(const char *const *msg)
{
	char expaddr[128];
	const char *netmsg[] = { "550 5.1.1 no such user <", expaddr, ">", NULL };
	unsigned int i;
	char *bracket;

	strcpy(expaddr, testdata[testindex].inpattern);
	bracket = strchr(expaddr, '>');
	if (bracket != NULL)
		*bracket = '\0';

	if (testdata[testindex].expect_net_writen == 0) {
		fprintf(stderr, "index %u: unexpected call to net_writen()\n",
				testindex);
		errcounter++;
		return -ECONNRESET;
	}

	testdata[testindex].expect_net_writen--;

	for (i = 0; netmsg[i] != NULL; i++) {
		if (msg[i] == NULL) {
			fprintf(stderr, "index %u: net_writen() had unexpected NULL string at index %i\n",
					testindex, i);
			errcounter++;
			return -ECONNRESET;
		}

		if (strcmp(netmsg[i], msg[i]) != 0) {
			fprintf(stderr, "index %u: string '%s' at index %i did not match expected one\n",
					testindex, msg[i], i);
			errcounter++;
			return -ECONNRESET;
		}
	}

	if (msg[i] != NULL) {
		fprintf(stderr, "index %u: net_writen() had unexpected extra strings\n",
				testindex);
		errcounter++;
		return -ECONNRESET;
	}

	return 0;
}

int
main(void)
{
	const char *rcpthosts = "example.net\nlocal.example.net\nliphost.example.net";
	const off_t rcpthsize = strlen(rcpthosts);

	liphost.s = "liphost.example.net";
	liphost.len = strlen(liphost.s);
	strcpy(xmitstat.localip, "192.0.2.4");

	testcase_setup_netnwrite(test_netnwrite);
	testcase_setup_net_writen(test_net_writen);

	for (testindex = 0; testdata[testindex].inpattern[0] != '\0'; testindex++) {
		struct string addr;
		char *more;
		struct userconf ds;

		userconf_init(&ds);
		STREMPTY(addr);

		const int r = addrparse(testdata[testindex].inpattern, testdata[testindex].flags,
				&addr, &more, &ds, rcpthosts, rcpthsize);

		if (r != testdata[testindex].parseresult) {
			fprintf(stderr, "index %u: expected result %i from addrparse(), but got %i\n",
					testindex, testdata[testindex].parseresult, r);
			errcounter++;
			userconf_free(&ds);
			free(addr.s);
			continue;
		}

		userconf_free(&ds);

		if (testdata[testindex].parseresult <= 0) {
			if (addr.len == 0) {
				if (testdata[testindex].parseresult == 0) {
					fprintf(stderr, "index %u: expected address not returned\n",
							testindex);
					errcounter++;
				}
			} else if ((strncmp(addr.s, testdata[testindex].inpattern, addr.len) != 0) ||
					(testdata[testindex].inpattern[addr.len] != '>')) {
				fprintf(stderr, "index %u: got '%s' instead of expected address\n",
						testindex, addr.s);
				errcounter++;
			}
		}

		free(addr.s);
	}

	return errcounter;
}
