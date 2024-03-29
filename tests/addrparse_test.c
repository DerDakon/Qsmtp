#include <qsmtpd/addrparse.h>

#include <netio.h>
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>
#include <sstring.h>
#include "test_io/testcase_io.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

static struct {
	char inpattern[128];	/* the input pattern to addrparse() */
	int flags;		/* the flags parameter to pass to addrparse() */
	const int syntaxresult;	/* the desired result of addrsyntax() */
	int expect_netwrite;	/* if call to netwrite() is expected */
	int expect_net_writen;	/* if call to net_writen() is expected */
	const int parseresult;	/* expected result of addrparse() */
	int expect_tarpit;	/* how often tarpit() is expected to be called */
	int userexists_result;	/* result to return from user_exists() */
} testdata[] = {
	{
		.inpattern = "missing@end.bracket",
		.expect_netwrite = 1,
		.parseresult = EBOGUS,
		.expect_tarpit = 2,
	},
	{
		.inpattern = "missing@end.bracket",
		.syntaxresult = -ENOMEM,
		.parseresult = ENOMEM,
	},
	{
		.inpattern = "postmaster>",
		.flags = 1,
		.syntaxresult = 1,
	},
	/* domain not in rcpthosts */
	{
		.inpattern = "user@example.com>",
		.flags = 1,
		.syntaxresult = 3,
		.parseresult = -2,
	},
	/* domain in rcpthosts, but not local */
	{
		.inpattern = "user@example.net>",
		.flags = 1,
		.syntaxresult = 3,
		.userexists_result = 5,
	},
	/* local domain, but user does not exist */
	{
		.inpattern = "user@local.example.net>",
		.flags = 1,
		.syntaxresult = 3,
		.expect_net_writen = 2,
		.parseresult = -1,
		.expect_tarpit = 2,
	},
	/* existing local user */
	{
		.inpattern = "existing@local.example.net>",
		.flags = 1,
		.syntaxresult = 3,
		.userexists_result = 1,
	},
	/* existing local user, addressed with IP address */
	{
		.inpattern = "existing@[192.0.2.4]>",
		.flags = 1,
		.syntaxresult = 4,
		.userexists_result = 1,
	},
	/* existing local user, but wrong IP address */
	{
		.inpattern = "existing@[192.0.2.42]>",
		.flags = 1,
		.syntaxresult = 4,
		.expect_net_writen = 2,
		.parseresult = -1,
		.expect_tarpit = 2,
	},
	/* existing local user, but user_exists() returns with error */
	{
		.inpattern = "existing@local.example.net>",
		.flags = 1,
		.syntaxresult = 3,
		.parseresult = ENOMEM,
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
char domaindirbuffer[DOMAINNAME_MAX + 1];

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
	ds->userconf = NULL;
	ds->domainconf = NULL;
	ds->domaindirfd = -1;
	ds->userdirfd = -1;
}

void
userconf_free(struct userconf *ds)
{
	assert((ds->domainpath.s == NULL) || (ds->domainpath.s == domaindirbuffer));
	free(ds->userconf);
	free(ds->domainconf);
	assert(ds->domaindirfd == -1);
	if (ds->userdirfd >= 0)
		close(ds->userdirfd);

	userconf_init(ds);
}

int
addrsyntax(char *in, const int flags, string *addr, char **more)
{
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

	const char * const bracket = strchr(in, '>');

	if (newstr(addr, bracket - in + 1)) {
		fprintf(stderr, "index %u: out of memory allocating %zu byte for addr\n",
				testindex, bracket - in + 1);
		exit(ENOMEM);
	}

	memcpy(addr->s, in, --addr->len);
	addr->s[addr->len] = '\0';

	return testdata[testindex].syntaxresult;
}

int
user_exists(const string *localpart, const char *domain, struct userconf *ds)
{
	if (ds != NULL) {
		assert(ds->domainpath.s == NULL);
		assert(ds->domainpath.len == 0);
		assert(ds->domaindirfd == -1);
		assert(ds->userdirfd == -1);
	}
	if (strchr(testdata[testindex].inpattern, '[') != NULL) {
		if (strcmp(domain, liphost.s) != 0) {
			fprintf(stderr, "index %u: domain '%s' passed to %s, but expected '%s'\n",
					testindex, domain, __func__, liphost.s);
			errcounter++;
			return -EINVAL;
		}
	} else {
		const char *at = strchr(testdata[testindex].inpattern, '@');
		if (at == NULL) {
			fprintf(stderr, "index %u: domain '%s' passed to %s, but no @ found in mail address\n",
					testindex, domain, __func__);
			errcounter++;
			return -EINVAL;
		}
		if (strncmp(domain, at + 1, strlen(domain)) != 0) {
			fprintf(stderr, "index %u: domain '%s' passed to %s\n",
					testindex, domain, __func__);
			errcounter++;
			return -EINVAL;
		}
	}
	assert(strncmp(testdata[testindex].inpattern, localpart->s, localpart->len) == 0);

	return testdata[testindex].userexists_result;
}

int
test_net_writen(const char *const *msg)
{
	char expaddr[128];
	const char *netmsg[] = { "550 5.1.1 no such user <", expaddr, ">", NULL };
	unsigned int i;

	strcpy(expaddr, testdata[testindex].inpattern);
	char *bracket = strchr(expaddr, '>');
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

	testcase_setup_netnwrite(testcase_netnwrite_compare);
	testcase_setup_net_writen(test_net_writen);

	for (testindex = 0; testdata[testindex].inpattern[0] != '\0'; testindex++) {
		struct string addr1 = STREMPTY_INIT, addr2 = STREMPTY_INIT;
		char *more;
		struct userconf ds;
		const char *netstring = "501 5.1.3 domain of mail address is syntactically incorrect\r\n";

		userconf_init(&ds);

		if (testdata[testindex].expect_netwrite > 0)
			netnwrite_msg = netstring;

		const int r = addrparse(testdata[testindex].inpattern, testdata[testindex].flags,
				&addr1, &more, &ds, rcpthosts, rcpthsize);

		if (testdata[testindex].expect_netwrite > 0) {
			if (netnwrite_msg != NULL) {
				fprintf(stderr, "index %u: expected call to netnwrite() did not happen\n", testindex);
				errcounter++;
			} else {
				netnwrite_msg = netstring;
			}
		}

		const int s = addrparse(testdata[testindex].inpattern, testdata[testindex].flags,
				&addr2, &more, NULL, rcpthosts, rcpthsize);

		if ((testdata[testindex].expect_netwrite > 0) && (netnwrite_msg != NULL)) {
			fprintf(stderr, "index %u: expected call to netnwrite() did not happen\n", testindex);
			errcounter++;
		}

		if (r != s) {
			fprintf(stderr, "index %u: call to addrparse() with ds pointer returned %i, "
					"but with NULL returned %i\n", testindex, r, s);
			errcounter++;
		}

		if ((addr1.len != addr2.len) || ((addr1.len != 0) && (memcmp(addr1.s, addr2.s, addr1.len) != 0))) {
			fprintf(stderr, "index %u: call to addrparse() with ds pointer returned addr %zu/%s, "
					"but with NULL returned %zu/%s\n", testindex, addr1.len, addr1.s, addr2.len, addr2.s);
			errcounter++;
		}

		free(addr2.s);

		if (r != testdata[testindex].parseresult) {
			fprintf(stderr, "index %u: expected result %i from addrparse(), but got %i\n",
					testindex, testdata[testindex].parseresult, r);
			errcounter++;
			userconf_free(&ds);
			free(addr1.s);
			continue;
		}

		userconf_free(&ds);

		if (testdata[testindex].parseresult <= 0) {
			if (addr1.len == 0) {
				if (testdata[testindex].parseresult == 0) {
					fprintf(stderr, "index %u: expected address not returned\n",
							testindex);
					errcounter++;
				}
			} else if ((strncmp(addr1.s, testdata[testindex].inpattern, addr1.len) != 0) ||
					(testdata[testindex].inpattern[addr1.len] != '>')) {
				fprintf(stderr, "index %u: got '%s' instead of expected address\n",
						testindex, addr1.s);
				errcounter++;
			}
		}

		free(addr1.s);
	}

	return errcounter;
}
