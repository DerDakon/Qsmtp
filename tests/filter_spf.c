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

	testcase_setup_netnwrite(testcase_netnwrite_compare);
	testcase_setup_log_writen(testcase_log_writen_combine);
	testcase_setup_log_write(testcase_log_write_compare);

	memset(&ds, 0, sizeof(ds));
	memset(&rcpt, 0, sizeof(rcpt));

	xmitstat.spf = SPF_PASS;

	r = cb_spf(NULL, NULL, NULL);
	if (r != FILTER_PASSED) {
		fprintf(stderr, "cb_spf(NULL, NULL, NULL) with spf == SPF_PASS returned %i instead of %i (FILTER_PASSED)\n",
				r, FILTER_PASSED);
		err++;
	}

	xmitstat.spf = SPF_IGNORE;

	r = cb_spf(NULL, NULL, NULL);
	if (r != FILTER_PASSED) {
		fprintf(stderr, "cb_spf(NULL, NULL, NULL) with spf == SPF_IGNORE returned %i instead of %i (FILTER_PASSED)\n",
				r, FILTER_PASSED);
		err++;
	}

	xmitstat.spf = SPF_NONE;

	r = cb_spf(NULL, NULL, NULL);
	if (r != FILTER_PASSED) {
		fprintf(stderr, "cb_spf() with getsettingglobal() returning 0 returned %i instead of %i (FILTER_PASSED)\n",
				r, FILTER_PASSED);
		err++;
	}

	xmitstat.spf = SPF_TEMP_ERROR;
	netnwrite_msg = "451 4.4.3 temporary error when checking the SPF policy\r\n";

	r = cb_spf(&ds, &logmsg, &t);
	if (r != FILTER_DENIED_WITH_MESSAGE) {
		fprintf(stderr, "cb_spf() with spf == SPF_TEMP_ERROR returned %i instead of %i (FILTER_DENIED_WITH_MESSAGE)\n",
				r, FILTER_DENIED_WITH_MESSAGE);
		err++;
	}

	if ((logmsg == NULL) || (strcmp(logmsg, "temp SPF") != 0)) {
		fprintf(stderr, "cb_spf() with spf == SPF_TEMP_ERROR set logmsg to '%s' instead of 'temp SPF'\n",
				logmsg);
		err++;
	}

	if (t != CONFIG_GLOBAL) {
		fprintf(stderr, "cb_spf() with spf == SPF_TEMP_ERROR set t to %i instead of %i (CONFIG_GLOBAL)\n",
				t, CONFIG_GLOBAL);
		err++;
	}

	err += testcase_netnwrite_check("cb_spf() with spf == SPF_TEMP_ERROR");

	xmitstat.remotehost.s = (char *)hostname_spfignore_fail;
	xmitstat.remotehost.len = strlen(xmitstat.remotehost.s);
	thisrecip = &rcpt;
	rcpt.to.s = "someone@example.org";
	rcpt.to.len = strlen(rcpt.to.s);
	logmsg = NULL;

	r = cb_spf(&ds, &logmsg, &t);
	if ((r != FILTER_ERROR) || (errno != ENOTBLK)) {
		fprintf(stderr, "cb_spf() with spf == SPF_TEMP_ERROR returned %i/%i instead of %i/%i (FILTER_ERROR/ENOTBLK)\n",
				r, errno, FILTER_ERROR, ENOTBLK);
		err++;
	}

	xmitstat.remotehost.s = (char *)hostname_spfignore;
	xmitstat.remotehost.len = strlen(xmitstat.remotehost.s);

	log_write_msg = "not rejected message to <someone@example.org> from <> from IP [] {SPF blocked by global policy, whitelisted by user policy}";
	log_write_priority = LOG_INFO;

	r = cb_spf(&ds, &logmsg, &t);
	if (r != FILTER_PASSED) {
		fprintf(stderr, "cb_spf() with spf == SPF_TEMP_ERROR and host in spfignore returned %i instead of %i (FILTER_PASSED)\n",
				r, FILTER_PASSED);
		err++;
	}

	xmitstat.spf = SPF_SOFTFAIL;
	xmitstat.helostr.s = "example.net";
	xmitstat.helostr.len = strlen(xmitstat.helostr.s);
	xmitstat.mailfrom.s = NULL;
	xmitstat.mailfrom.len = 0;
	xmitstat.remotehost.s = NULL;
	xmitstat.remotehost.len = 0;

	r = cb_spf(&ds, &logmsg, &t);
	if (r != FILTER_PASSED) {
		fprintf(stderr, "cb_spf() with spf == SPF_SOFTFAIL returned %i instead of %i (FILTER_PASSED)\n",
				r, FILTER_PASSED);
		err++;
	}

	xmitstat.spf = SPF_SOFTFAIL;
	xmitstat.mailfrom.s = "someone@spfstrict.example.com";
	xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);
	xmitstat.remotehost.s = (char *)hostname_spfstrict;
	xmitstat.remotehost.len = strlen(xmitstat.remotehost.s);
	netnwrite_msg = "550 5.7.1 mail denied by SPF policy\r\n";

	r = cb_spf(&ds, &logmsg, &t);
	if (r != FILTER_DENIED_WITH_MESSAGE) {
		fprintf(stderr, "cb_spf() with spf == SPF_SOFTFAIL and spfstrict host returned %i instead of %i (FILTER_DENIED_WITH_MESSAGE)\n",
				r, FILTER_DENIED_WITH_MESSAGE);
		err++;
	}

	if ((logmsg == NULL) || (strcmp(logmsg, "SPF") != 0)) {
		fprintf(stderr, "cb_spf() with spf == SPF_SOFTFAIL and spfstrict host set logmsg to '%s' instead of 'SPF'\n",
				logmsg);
		err++;
	}

	if (t != CONFIG_DOMAIN) {
		fprintf(stderr, "cb_spf() with spf == SPF_SOFTFAIL and spfstrict host set t to %i instead of %i (CONFIG_DOMAIN)\n",
				t, CONFIG_DOMAIN);
		err++;
	}

	return err;
}
