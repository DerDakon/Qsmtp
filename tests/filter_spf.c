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

/* This test (ab)uses the fields in struct userconf to set the expected
 * results of getsetting() and getsettingglobal().
 *
 * userdirfd & 0xff00   -> config domain (must only be user, domain, or none)
 * userdirfd & 0x0001   -> return value for getsetting(ds, "fail_hard_on_temp", t)
 *
 * domaindirfd & 0xff00 -> config domain (all values permitted)
 * domaindirfd & 0x00ff -> return value for getsettingglobal(ds, "spfpolicy", t)
 */

static enum config_domain
decode_config_domain(const int i)
{
	const int t = (i & 0xff00) >> 8;

	switch (t) {
	case CONFIG_DOMAIN:
	case CONFIG_USER:
	case CONFIG_GLOBAL:
		return t;
	default:
		assert(i == 0);
		return CONFIG_NONE;
	}
}

long
getsetting(const struct userconf *ds, const char *c, enum config_domain  *t)
{
	assert(strcmp(c, "fail_hard_on_temp") == 0);

	*t = decode_config_domain(ds->userdirfd);
	assert(*t != CONFIG_GLOBAL);

	int i = (ds->userdirfd & 0xff);
	((struct userconf *)ds)->userdirfd = 0;

	return i;
}

long
getsettingglobal(const struct userconf *ds, const char *c, enum config_domain *t)
{
	assert(strcmp(c, "spfpolicy") == 0);

	if (ds == NULL)
		return 0;

	*t = decode_config_domain(ds->domaindirfd);

	int i = (ds->domaindirfd & 0xff);
	((struct userconf *)ds)->domaindirfd = 0;

	return i;
}

int
domainvalid(const char * const domain __attribute__ ((unused)))
{
	abort();
}

static const char *rspf_buffer;

int
userconf_get_buffer(const struct userconf *ds __attribute__ ((unused)), const char *key,
		char ***values, checkfunc cf __attribute__ ((unused)), const unsigned int flags)
{
	assert(flags & userconf_global);

	if (strcmp(key, "rspf") == 0) {
		if (rspf_buffer != NULL) {
			*values = data_array(1, strlen(rspf_buffer) + 2, 0, 0);
			if (*values == NULL)
				exit(ENOMEM);
			(*values)[0] = (char *)(*values + 2);
			strcpy((*values)[0], rspf_buffer);
			return CONFIG_USER;
		} else {
			return CONFIG_NONE;
		}
	}

	abort();
}

static const char hostname_spfignore[] = "spfignore.example.com";
static const char hostname_spfignore_fail[] = "failure.spfignore.example.com";
static const char hostname_spfstrict[] = "spfstrict.example.com";

int
userconf_find_domain(const struct userconf *ds __attribute__ ((unused)), const char *key,
		const char *domain, const unsigned int flags)
{
	assert(flags & userconf_global);

	if (strcmp(key, "spfignore") == 0) {
		if (strcmp(domain, hostname_spfignore) == 0)
			return CONFIG_USER;
		else if (strcmp(domain, hostname_spfignore_fail) == 0)
			return -ENOTBLK;
		else
			return CONFIG_NONE;
	} else if (strcmp(key, "spfstrict") == 0) {
		if ((domain != NULL) && (strcmp(domain, hostname_spfstrict) == 0))
			return CONFIG_DOMAIN;
		else
			return CONFIG_NONE;
	}

	abort();
}

int
check_host(const char *domain)
{
	if (rspf_buffer != NULL) {
		const char *end = strstr(domain, rspf_buffer);
		// check that the rspf_buffer is at the end of the passed domain
		if ((end == NULL) || (end == domain) || (strlen(end) != strlen(rspf_buffer)) || (*(end - 1) != '.'))
			abort();

		if (strncmp(domain, "match.", strlen("match.")) == 0)
			return SPF_FAIL;
		else if (strncmp(domain, "pass.", strlen("pass.")) == 0)
			return SPF_PASS;
		else if (strncmp(domain, "miss.", strlen("miss.")) == 0)
			return SPF_NONE;
	}

	abort();
}

int
main(void)
{
	int err = 0;
	struct userconf ds;
	const char *logmsg = NULL;
	enum config_domain t = CONFIG_NONE;
	struct recip rcpt;
	struct {
		/* input values */
		const char *name;
		const char *remotehost;
		const char *helo;
		const char *mailfrom;
		const char *spfexp;
		const char *rspf;

		const unsigned int spf:4;		/* the SPF status to test */
		const unsigned int use_rcpt:1;	/* set thisrecip */

		const unsigned int no_params:1;	/* pass NULL values for all parameters */
		const unsigned char spfpolicy;	/* config value for spfpolicy */
		const unsigned char tempsetting;	/* config value for fail_hard_on_temp */

		const enum config_domain cd_policy;	/* domain for spfpolicy */
		const enum config_domain cd_temp;	/* domain for fail_hard_on_temp */

		/* output */
		const int expected_result;
		const int expected_errno;

		const char *expected_logmsg;
		const char *expected_netmsg;
		const char *expected_syslogmsg;

		const enum config_domain expected_t;
		const int expected_syslogprio;
	} testpatterns[] = {
		{
			.name = "spf == SPF_PASS",
			.spf = SPF_PASS,
			.no_params = 1,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_IGNORE",
			.spf = SPF_IGNORE,
			.no_params = 1,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_NONE",
			.spf = SPF_NONE,
			.no_params = 1,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_NONE with rspf attempt",
			.spf = SPF_NONE,
			.spfpolicy = 1,
			.cd_policy = CONFIG_GLOBAL,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_NONE with rspf pass",
			.rspf = "rspf.example.com",
			.helo = "pass.example.com",
			.spf = SPF_NONE,
			.spfpolicy = 1,
			.cd_policy = CONFIG_GLOBAL,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_NONE with rspf miss",
			.rspf = "rspf.example.com",
			.helo = "miss.example.com",
			.spf = SPF_NONE,
			.spfpolicy = 1,
			.cd_policy = CONFIG_GLOBAL,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_NONE with rspf match",
			.rspf = "rspf.example.com",
			.mailfrom = "foo@match.example.com",
			.spf = SPF_NONE,
			.spfpolicy = 2,
			.cd_policy = CONFIG_GLOBAL,
			.expected_result = FILTER_DENIED_WITH_MESSAGE,
			.expected_netmsg = "550 5.7.1 mail denied by SPF policy\r\n",
			.expected_logmsg = "rSPF",
			.expected_t = CONFIG_USER
		},
		{
			.name = "spf == SPF_NONE with rspf overflow",
			.rspf = "the.combined.length.of.both.domain.names.will.exceed.domainname-max.because.these.names.are.very.loong.blacklist.rspf.example.com",
			.helo = "match.the.combined.length.of.both.domain.names.will.exceed.domainname-max.because.these.names.are.very.long.heloname.example.com",
			.spf = SPF_NONE,
			.spfpolicy = 1,
			.cd_policy = CONFIG_GLOBAL,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_TEMPERROR",
			.spf = SPF_TEMPERROR,
			.spfpolicy = 1,
			.cd_policy = CONFIG_GLOBAL,
			.expected_result = FILTER_DENIED_WITH_MESSAGE,
			.expected_logmsg = "temp SPF",
			.expected_netmsg = "451 4.4.3 temporary error when checking the SPF policy\r\n",
			.expected_t = CONFIG_GLOBAL
		},
		{
			.name = "spf == SPF_TEMPERROR with fail_hard_on_temp",
			.spf = SPF_TEMPERROR,
			.spfpolicy = 1,
			.tempsetting = 1,
			.cd_policy = CONFIG_GLOBAL,
			.cd_temp = CONFIG_USER,
			.expected_result = FILTER_DENIED_TEMPORARY,
			.expected_logmsg = "SPF",
			.expected_t = CONFIG_GLOBAL
		},
		{
			.name = "error in userconf_find_domain()",
			.remotehost = hostname_spfignore_fail,
			.spf = SPF_TEMPERROR,
			.spfpolicy = 1,
			.cd_policy = CONFIG_USER,
			.expected_result = FILTER_ERROR,
			.expected_errno = ENOTBLK
		},
		{
			.name = "hostname in spfignore",
			.remotehost = hostname_spfignore,
			.spf = SPF_TEMPERROR,
			.use_rcpt = 1,
			.spfpolicy = 1,
			.cd_policy = CONFIG_GLOBAL,
			.expected_result = FILTER_PASSED,
			.expected_syslogmsg = "not rejected message to <someone@example.org> from <> from IP [] {SPF blocked by global policy, whitelisted by user policy}",
			.expected_syslogprio = LOG_INFO
		},
		{
			.name = "spf == SPF_SOFTFAIL with spfpolicy 1",
			.spf = SPF_SOFTFAIL,
			.helo = "example.net",
			.spfpolicy = 1,
			.cd_policy = CONFIG_USER,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_SOFTFAIL with strict match",
			.remotehost = hostname_spfstrict,
			.mailfrom = "someone@spfstrict.example.com",
			.spf = SPF_SOFTFAIL,
			.spfpolicy = 1,
			.cd_policy = CONFIG_DOMAIN,
			.expected_result = FILTER_DENIED_WITH_MESSAGE,
			.expected_netmsg = "550 5.7.1 mail denied by SPF policy\r\n",
			.expected_logmsg = "SPF",
			.expected_t = CONFIG_DOMAIN
		},
		{
			.name = "simple reject",
			.spf = SPF_FAIL,
			.helo = "example.net",
			.spfpolicy = 2,
			.cd_policy = CONFIG_USER,
			.expected_result = FILTER_DENIED_WITH_MESSAGE,
			.expected_netmsg = "550 5.7.1 mail denied by SPF policy\r\n",
			.expected_logmsg = "SPF",
			.expected_t = CONFIG_USER
		},
		{
			.name = "simple reject with message",
			.spf = SPF_FAIL,
			.spfexp = "SPFEXP message",
			.helo = "example.net",
			.spfpolicy = 2,
			.cd_policy = CONFIG_USER,
			.expected_result = FILTER_DENIED_WITH_MESSAGE,
			.expected_netmsg = "550 5.7.1 mail denied by SPF policy, SPF record says: SPFEXP message\r\n",
			.expected_logmsg = "SPF",
			.expected_t = CONFIG_USER
		},
		{
			.name = "spf == SPF_DNS_HARD_ERROR and spfpolicy = 2",
			.spf = SPF_DNS_HARD_ERROR,
			.spfpolicy = 2,
			.cd_policy = CONFIG_DOMAIN,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_DNS_HARD_ERROR and spfpolicy = 3",
			.spf = SPF_DNS_HARD_ERROR,
			.spfpolicy = 3,
			.cd_policy = CONFIG_DOMAIN,
			.expected_result = FILTER_DENIED_WITH_MESSAGE,
			.expected_netmsg = "550 5.5.2 syntax error in SPF record\r\n",
			.expected_logmsg = "bad SPF",
			.expected_t = CONFIG_DOMAIN
		},
		{
			.name = "spf == SPF_SOFTFAIL and spfpolicy = 3",
			.spf = SPF_SOFTFAIL,
			.spfpolicy = 3,
			.cd_policy = CONFIG_DOMAIN,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_SOFTFAIL and spfpolicy = 4",
			.spf = SPF_SOFTFAIL,
			.spfpolicy = 4,
			.cd_policy = CONFIG_DOMAIN,
			.expected_result = FILTER_DENIED_WITH_MESSAGE,
			.expected_netmsg = "550 5.7.1 mail denied by SPF policy\r\n",
			.expected_logmsg = "SPF",
			.expected_t = CONFIG_DOMAIN
		},
		{
			.name = "spf == SPF_NEUTRAL and spfpolicy = 4",
			.spf = SPF_NEUTRAL,
			.spfpolicy = 4,
			.cd_policy = CONFIG_DOMAIN,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_NEUTRAL and spfpolicy = 5",
			.spf = SPF_NEUTRAL,
			.spfpolicy = 5,
			.cd_policy = CONFIG_DOMAIN,
			.expected_result = FILTER_DENIED_WITH_MESSAGE,
			.expected_netmsg = "550 5.7.1 mail denied by SPF policy\r\n",
			.expected_logmsg = "SPF",
			.expected_t = CONFIG_DOMAIN
		},
		{
			.name = "spf == SPF_NONE and spfpolicy = 5",
			.spf = SPF_NONE,
			.spfpolicy = 5,
			.cd_policy = CONFIG_DOMAIN,
			.expected_result = FILTER_PASSED
		},
		{
			.name = "spf == SPF_NONE and spfpolicy = 6",
			.spf = SPF_NONE,
			.spfpolicy = 6,
			.cd_policy = CONFIG_DOMAIN,
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
	testcase_setup_net_writen(testcase_net_writen_combine);
	testcase_setup_log_writen(testcase_log_writen_combine);
	testcase_setup_log_write(testcase_log_write_compare);

	memset(&ds, 0, sizeof(ds));
	memset(&rcpt, 0, sizeof(rcpt));
	rcpt.to.s = "someone@example.org";
	rcpt.to.len = strlen(rcpt.to.s);

	for (unsigned int i = 0; testpatterns[i].name != NULL; i++) {
		xmitstat.spf = testpatterns[i].spf;
		xmitstat.spfexp = (char *)testpatterns[i].spfexp;
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

		rspf_buffer = testpatterns[i].rspf;

		if (testpatterns[i].tempsetting == 0)
			ds.userdirfd = 0;
		else
			ds.userdirfd = (testpatterns[i].cd_temp << 8) | testpatterns[i].tempsetting;
		if (testpatterns[i].spfpolicy == 0)
			ds.domaindirfd = 0;
		else
			ds.domaindirfd = (testpatterns[i].cd_policy << 8) | testpatterns[i].spfpolicy;

		printf("testing: %s\n", testpatterns[i].name);

		int r;
		if (testpatterns[i].no_params)
			r = cb_spf(NULL, NULL, NULL);
		else
			r = cb_spf(&ds, &logmsg, &t);
		if (r != testpatterns[i].expected_result) {
			fprintf(stderr, "test %s: cb_spf() returned %i instead of %i\n",
					testpatterns[i].name,
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
					fprintf(stderr, "test %s: cb_spf() set errno to %i instead of %i\n",
							testpatterns[i].name,
							errno, testpatterns[i].expected_errno);
					err++;
				}
			}
		} else {
			assert(testpatterns[i].expected_logmsg != NULL);
			assert(testpatterns[i].expected_t != CONFIG_NONE);
			assert(testpatterns[i].expected_errno == 0);

			if ((logmsg == NULL) || (strcmp(logmsg, testpatterns[i].expected_logmsg) != 0)) {
				fprintf(stderr, "test %s: cb_spf() set logmsg to '%s' instead of '%s'\n",
						testpatterns[i].name,
						logmsg, testpatterns[i].expected_logmsg);
				err++;
			}

			if (t != testpatterns[i].expected_t) {
				fprintf(stderr, "test %s: cb_spf() set t to %i instead of %i\n",
						testpatterns[i].name,
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
		if (ds.domaindirfd != 0) {
			fprintf(stderr, "test %s: expected call to getsettingglobal() did not happen\n",
					testpatterns[i].name);
			err++;
		}
		if (ds.userdirfd != 0) {
			fprintf(stderr, "test %s: expected call to getsettingglobal() did not happen\n",
					testpatterns[i].name);
			err++;
		}
	}

	return err;
}
