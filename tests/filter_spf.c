#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userfilters.h>
#include <qsmtpd/userconf.h>
#include <qsmtpd/antispam.h>

#include "test_io/testcase_io.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

struct xmitstat xmitstat;
struct recip *thisrecip;

enum filter_result cb_nomail(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_boolean(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_badmailfrom(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_dnsbl(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_check2822(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_ipbl(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_badcc(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_fromdomain(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_smtpbugs(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
extern enum filter_result cb_spf(const struct userconf *, const char **, enum config_domain *);
enum filter_result cb_soberg(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_helo(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_usersize(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_forceesmtp(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_namebl(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }
enum filter_result cb_wildcardns(const struct userconf *d __attribute__ ((unused)), const char **l __attribute__ ((unused)), enum config_domain *t __attribute__ ((unused))) { abort(); }

long
getsetting(const struct userconf *ds __attribute__ ((unused)), const char *c, enum config_domain  *t)
{
	assert(strcmp(c, "fail_hard_on_temp") == 0);

	*t = CONFIG_NONE;

	return 0;
}

long
getsettingglobal(const struct userconf *ds, const char *c, enum config_domain *t)
{
	assert(strcmp(c, "spfpolicy") == 0);

	if (ds == NULL)
		return 0;

	if (ds->userdirfd > 0) {
		*t = CONFIG_USER;
		return ds->userdirfd;
	} else if (ds->domaindirfd > 0) {
		*t = CONFIG_DOMAIN;
		return ds->domaindirfd;
	} else {
		*t = CONFIG_GLOBAL;
		return 1;
	}
}

int
domainvalid(const char * const domain __attribute__ ((unused)))
{
	abort();
}

int
userconf_get_buffer(const struct userconf *ds __attribute__ ((unused)), const char *key,
		char ***values __attribute__ ((unused)), checkfunc cf __attribute__ ((unused)), const int useglobal)
{
	assert(useglobal == 1);

	if (strcmp(key, "rspf") == 0) {
	}

	abort();
}

static const char hostname_spfignore[] = "spfignore.example.com";
static const char hostname_spfignore_fail[] = "failure.spfignore.example.com";
static const char hostname_spfstrict[] = "spfstrict.example.com";

int
userconf_find_domain(const struct userconf *ds __attribute__ ((unused)), const char *key,
		const char *domain, const int useglobal)
{
	assert(useglobal == 1);

	if (strcmp(key, "spfignore") == 0) {
		if (strcmp(domain, hostname_spfignore) == 0)
			return CONFIG_USER;
		else if (strcmp(domain, hostname_spfignore_fail) == 0)
			return -ENOTBLK;
		else
			return CONFIG_NONE;
	} else if (strcmp(key, "spfstrict") == 0) {
		if (strcmp(domain, hostname_spfstrict) == 0)
			return CONFIG_DOMAIN;
		else
			return CONFIG_NONE;
	}

	abort();
}

int
check_host(const char *domain __attribute__ ((unused)))
{
	abort();
}

int
main(void)
{
	int err = 0;
	struct userconf ds;
	const char *logmsg = NULL;
	int r;
	enum config_domain t = CONFIG_NONE;
	struct recip rcpt;
	unsigned int i;
	struct {
		/* input values */
		const char *name;
		const char *remotehost;
		const char *helo;
		const char *mailfrom;

		const unsigned int spf:4;		/* the SPF status to test */
		const unsigned int use_rcpt:1;	/* set thisrecip */
		const unsigned int use_params:1;	/* set userconf, logmsg and t parameters */

		/* output */
		const int expected_result;

		const int expected_errno;
		const enum config_domain expected_t;

		const char *expected_logmsg;
		const char *expected_netmsg;
		const char *expected_syslogmsg;

		const int expected_syslogprio;
	} testpatterns[] = {
		{
			.name = "spf == SPF_PASS",
			.spf = SPF_PASS,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_IGNORE",
			.spf = SPF_IGNORE,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_NONE",
			.spf = SPF_NONE,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_TEMP_ERROR",
			.spf = SPF_TEMP_ERROR,
			.use_params = 1,
			.expected_result = FILTER_DENIED_WITH_MESSAGE,
			.expected_logmsg = "temp SPF",
			.expected_netmsg = "451 4.4.3 temporary error when checking the SPF policy\r\n",
			.expected_t = CONFIG_GLOBAL
		},
		{
			.name = "error in userconf_find_domain()",
			.remotehost = hostname_spfignore_fail,
			.spf = SPF_TEMP_ERROR,
			.use_params = 1,
			.expected_result = FILTER_ERROR,
			.expected_errno = ENOTBLK
		},
		{
			.name = "hostname in spfignore",
			.remotehost = hostname_spfignore,
			.spf = SPF_TEMP_ERROR,
			.use_rcpt = 1,
			.use_params = 1,
			.expected_result = FILTER_PASSED,
			.expected_syslogmsg = "not rejected message to <someone@example.org> from <> from IP [] {SPF blocked by global policy, whitelisted by user policy}",
			.expected_syslogprio = LOG_INFO
		},
		{
			.name = "spf == SPF_SOFTFAIL",
			.spf = SPF_SOFTFAIL,
			.use_params = 1,
			.helo = "example.net",
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_SOFTFAIL",
			.remotehost = hostname_spfstrict,
			.mailfrom = "someone@spfstrict.example.com",
			.spf = SPF_SOFTFAIL,
			.use_params = 1,
			.expected_result = FILTER_DENIED_WITH_MESSAGE,
			.expected_netmsg = "550 5.7.1 mail denied by SPF policy\r\n",
			.expected_logmsg = "SPF",
			.expected_t = CONFIG_DOMAIN
		},
		{
			.name = NULL
		}
	};

	testcase_setup_netnwrite(testcase_netnwrite_compare);
	testcase_setup_log_writen(testcase_log_writen_combine);
	testcase_setup_log_write(testcase_log_write_compare);

	memset(&ds, 0, sizeof(ds));
	memset(&rcpt, 0, sizeof(rcpt));
	rcpt.to.s = "someone@example.org";
	rcpt.to.len = strlen(rcpt.to.s);

	for (i = 0; testpatterns[i].name != NULL; i++) {
		struct userconf *pds = testpatterns[i].use_params ? &ds : NULL;
		const char **plogmsg = testpatterns[i].use_params ? &logmsg : NULL;
		enum config_domain *pt = testpatterns[i].use_params ? &t : NULL;

		xmitstat.spf = testpatterns[i].spf;
		netnwrite_msg = testpatterns[i].expected_netmsg;
		log_write_msg = testpatterns[i].expected_syslogmsg;
		log_write_priority = testpatterns[i].expected_syslogprio;
		xmitstat.remotehost.s = (char *)testpatterns[i].remotehost;
		if (testpatterns[i].remotehost != NULL)
			xmitstat.remotehost.len = strlen(xmitstat.remotehost.s);
		else
			xmitstat.remotehost.len = 0;
		xmitstat.helostr.s = (char *)testpatterns[i].helo;
		if (testpatterns[i].helo != NULL)
			xmitstat.helostr.len = strlen(testpatterns[i].helo);
		else
			xmitstat.helostr.len = 0;
		xmitstat.mailfrom.s = (char *)testpatterns[i].mailfrom;
		if (testpatterns[i].mailfrom != NULL)
			xmitstat.mailfrom.len = strlen(testpatterns[i].mailfrom);
		else
			xmitstat.mailfrom.len = 0;
		logmsg = NULL;
		t = CONFIG_NONE;
		if (testpatterns[i].use_rcpt)
			thisrecip = &rcpt;
		else
			thisrecip = NULL;

		printf("testing: %s\n", testpatterns[i].name);

		r = cb_spf(pds, plogmsg, pt);
		if (r != testpatterns[i].expected_result) {
			fprintf(stderr, "test %s: cb_spf(%s, %s, %s) returned %i instead of %i\n",
					testpatterns[i].name,
					pds ? "&ds" : "NULL", plogmsg ? "&logmsg" : "NULL", pt ? "&t" : "NULL",
					r, testpatterns[i].expected_result);
			err++;
		}

		if ((testpatterns[i].expected_result == FILTER_PASSED) || (testpatterns[i].expected_result == FILTER_ERROR)) {
			assert(testpatterns[i].expected_logmsg == NULL);
			assert(testpatterns[i].expected_t == 0);
			if (testpatterns[i].expected_result == FILTER_PASSED) {
				assert(testpatterns[i].expected_errno == 0);
			} else {
				assert(testpatterns[i].expected_errno != 0);
				if (errno != testpatterns[i].expected_errno) {
					fprintf(stderr, "test %s: cb_spf(%s, %s, %s) set errno to %i instead of %i\n",
							testpatterns[i].name,
							pds ? "&ds" : "NULL", plogmsg ? "&logmsg" : "NULL", pt ? "&t" : "NULL",
							errno, testpatterns[i].expected_errno);
					err++;
				}
			}
		} else {
			assert(testpatterns[i].expected_logmsg != NULL);
			assert(testpatterns[i].expected_t != CONFIG_NONE);
			assert(testpatterns[i].expected_errno == 0);

			if ((logmsg == NULL) || (strcmp(logmsg, testpatterns[i].expected_logmsg) != 0)) {
				fprintf(stderr, "test %s: cb_spf(%s, %s, %s) set logmsg to '%s' instead of '%s'\n",
						testpatterns[i].name,
						pds ? "&ds" : "NULL", plogmsg ? "&logmsg" : "NULL", pt ? "&t" : "NULL",
						logmsg, testpatterns[i].expected_logmsg);
				err++;
			}

			if (t != testpatterns[i].expected_t) {
				fprintf(stderr, "test %s: cb_spf(%s, %s, %s) set t to %i instead of %i\n",
						testpatterns[i].name,
						pds ? "&ds" : "NULL", plogmsg ? "&logmsg" : "NULL", pt ? "&t" : "NULL",
						t, testpatterns[i].expected_t);
				err++;
			}
		}

		err += testcase_netnwrite_check(testpatterns[i].name);
		if (log_write_msg != NULL) {
			fprintf(stderr, "test %s: expected syslog message '%s' was not sent\n",
					testpatterns[i].name, testpatterns[i].expected_syslogmsg);
			err++;
		}
	}

	return err;
}
