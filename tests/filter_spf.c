#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userfilters.h>
#include <qsmtpd/userconf.h>
#include <qsmtpd/antispam.h>

#include "test_io/testcase_io.h"

#include <assert.h>
#include <string.h>

struct xmitstat xmitstat;

extern enum filter_result cb_spf(const struct userconf *ds, const char **logmsg, enum config_domain *t);

long
getsetting(const struct userconf *ds __attribute__ ((unused)), const char *c __attribute__ ((unused)),
		enum config_domain  *t __attribute__ ((unused)))
{
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

int
userconf_find_domain(const struct userconf *ds __attribute__ ((unused)), const char *key,
		const char *domain __attribute__ ((unused)), const int useglobal)
{
	assert(useglobal == 1);

	if (strcmp(key, "spfignore") == 0) {
	} else if (strcmp(key, "spfstrict") == 0) {
	}

	abort();
}

int
check_host(const char *domain __attribute__ ((unused)))
{
	abort();
}

void
logwhitelisted(const char *a __attribute__ ((unused)), const int b __attribute__ ((unused)), const int c __attribute__ ((unused)))
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

	testcase_setup_netnwrite(testcase_netnwrite_compare);

	memset(&ds, 0, sizeof(ds));

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

	return err;
}
