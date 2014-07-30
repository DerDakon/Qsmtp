#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <qsmtpd/userfilters.h>

#include <qsmtpd/antispam.h>
#include "log.h"
#include <qsmtpd/qsmtpd.h>

enum filter_result
cb_ipbl(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	int i;			/* counter of the array position */
	enum filter_result rc;	/* return code */
	int fd;			/* file descriptor of the policy file */
	const char *fnb;	/* filename of the blacklist file */
	const char *fnw;	/* filename of the whitelist file */

	if (connection_is_ipv4()) {
		fnb = "ipbl";
		fnw = "ipwl";
	} else {
		fnb = "ipblv6";
		fnw = "ipwlv6";
	}

	if ( (fd = getfile(ds, fnb, t, 1)) < 0)
		return (errno == ENOENT) ? FILTER_PASSED : FILTER_ERROR;

	i = lookupipbl(fd);
	if (errno == ENOLCK)
		return FILTER_PASSED;

	if (i > 0) {
		enum config_domain u;

		if ( (fd = getfile(ds, fnw, &u, 1)) < 0) {
			if (errno != ENOENT)
				return FILTER_ERROR;
			i = 0;
		} else {
			i = lookupipbl(fd);
		}
		if (i > 0) {
			logwhitelisted("ipbl", *t, u);
			rc = FILTER_PASSED;
		} else if (!i) {
			*logmsg = "ipbl";
			rc = FILTER_DENIED_UNSPECIFIC;
		} else {
			const char *logmess[] = {"bad input data in ", blocktype[u],
						"ipwl file for address <", THISRCPT, ">", NULL};
			log_writen(LOG_ERR, logmess);
			rc = FILTER_PASSED;
		}
	} else {
		if (i) {
			const char *logmess[] = {"bad input data in ", blocktype[*t],
						"ipbl file for address <", THISRCPT, ">", NULL};

			log_writen(LOG_ERR, logmess);
		}
		rc = FILTER_PASSED;
	}
	return rc;
}
