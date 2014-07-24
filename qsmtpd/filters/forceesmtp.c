#include <qsmtpd/userfilters.h>

#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <qsmtpd/antispam.h>
#include "control.h"
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>

int
cb_forceesmtp(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	char **a;		/* array of domains and/or mailaddresses to block */
	int i;			/* counter of the array position */
	int rc;			/* return code */
	const char *fnb;	/* filename of the blacklist file */

	if (xmitstat.esmtp)
		return 0;

	if (connection_is_ipv4()) {
		fnb = "forceesmtp";
	} else {
		fnb = "forceesmtpv6";
	}

	*t = userconf_get_buffer(ds, fnb, &a, domainvalid, 1);
	if (((int)*t) < 0) {
		errno = -*t;
		return -1;
	} else if (*t == CONFIG_NONE) {
		return 0;
	}

	i = check_rbl(a, NULL);
	free(a);
	if (i < 0) {
		if (errno) {
			if (errno == EAGAIN) {
				*logmsg = "temporary DNS error on RBL lookup";
				rc = 4;
			} else {
				rc = -1;
			}
		} else {
			rc = 0;
		}
	} else {
		*logmsg = "ESMTP forced";
		rc = 2;
	}
	return rc;
}
