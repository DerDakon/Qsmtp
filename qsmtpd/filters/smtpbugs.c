/** \file smtpbugs.c
 \brief reject mail when sending SMTP engine is not standard compliant
 */
#include <qsmtpd/userfilters.h>

#include <syslog.h>
#include "log.h"
#include "netio.h"
#include <qsmtpd/qsmtpd.h>
#include "tls.h"

enum spacebug_filter {
	SPB_PERMIT_ALL = 0,
	SPB_PERMIT_ESMTP = 1,
	SPB_PERMIT_TLS = 2,
	SPB_PERMIT_AUTH = 3,
	SPB_REJECT_ALL = 255
};

int
cb_smtpbugs(const struct userconf *ds, const char **logmsg __attribute__ ((unused)), enum config_domain *t)
{
	int rc;
	int filter;
	const char *logmess[] = {"rejected message to <", THISRCPT, "> from <", MAILFROM,
			"> from IP [", xmitstat.remoteip, "] {SMTP space bug}", NULL};

	if (xmitstat.spacebug == 0)
		return 0;

	if ((filter = getsettingglobal(ds, "smtp_space_bug", t)) <= 0)
		return 0;

	switch (filter) {
	case SPB_PERMIT_TLS:
		if (ssl)
			return 0;
		/* fallthrough */
	case SPB_PERMIT_AUTH:
		if (xmitstat.authname.len > 0)
			return 0;
		break;
	case SPB_PERMIT_ESMTP:
		if (xmitstat.esmtp)
			return 0;
		break;
	case SPB_REJECT_ALL:
		break;
	default: {
		const char *logval[] = {"unknown value for smtp_space_bug for address <", THISRCPT, ">", NULL};
		log_writen(LOG_ERR, logval);
		return 0;
		}
	}

	log_writen(LOG_INFO, logmess);

	rc = netwrite("500 5.5.2 command syntax error\r\n");
	if (rc != 0)
		return -1;

	return 1;
}
