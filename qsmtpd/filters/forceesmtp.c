#include <qsmtpd/userfilters.h>

#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <qsmtpd/antispam.h>
#include "control.h"
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>

enum filter_result
cb_forceesmtp(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	char **a;		/* array of domains and/or mailaddresses to block */
	int i;			/* counter of the array position */
	enum filter_result rc;	/* return code */
	const char *fnb;	/* filename of the blacklist file */

	if (xmitstat.esmtp)
		return FILTER_PASSED;

	if (connection_is_ipv4()) {
		fnb = "forceesmtp";
	} else {
		fnb = "forceesmtpv6";
	}

	*t = userconf_get_buffer(ds, fnb, &a, domainvalid, userconf_global);
	if (((int)*t) < 0) {
		errno = -*t;
		return FILTER_ERROR;
	} else if (*t == CONFIG_NONE) {
		return FILTER_PASSED;
	}

	i = check_rbl(a, NULL);
	free(a);
	if (i < 0) {
		if (errno) {
			if (errno == EAGAIN) {
				*logmsg = "temporary DNS error on RBL lookup";
				rc = FILTER_DENIED_TEMPORARY;
			} else {
				rc = FILTER_ERROR;
			}
		} else {
			rc = FILTER_PASSED;
		}
	} else {
		*logmsg = "ESMTP forced";
		rc = FILTER_DENIED_UNSPECIFIC;
	}
	return rc;
}
