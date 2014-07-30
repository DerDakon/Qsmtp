/** \file smtpbugs.c
 \brief reject mail when sending SMTP engine is not standard compliant
 */
#include <qsmtpd/userfilters.h>

#include <syslog.h>
#include "log.h"
#include "netio.h"
#include <qsmtpd/qsmtpd.h>
#include "tls.h"

/** @enum spacebug_filter
 * @brief the defined configuration values for the "SMTP space bug" filter
 */
enum spacebug_filter {
	SPB_PERMIT_ALL = 0,
	SPB_PERMIT_ESMTP = 1,
	SPB_PERMIT_TLS = 2,
	SPB_PERMIT_AUTH = 3,
	SPB_REJECT_ALL = 255
};

enum filter_result
cb_smtpbugs(const struct userconf *ds, const char **logmsg __attribute__ ((unused)), enum config_domain *t)
{
	int filter;
	const char *logmess[] = {"rejected message to <", THISRCPT, "> from <", MAILFROM,
			"> from IP [", xmitstat.remoteip, "] {SMTP space bug}", NULL};

	if (xmitstat.spacebug == 0)
		return FILTER_PASSED;

	if ((filter = getsettingglobal(ds, "smtp_space_bug", t)) <= 0)
		return FILTER_PASSED;

	switch (filter) {
	case SPB_PERMIT_TLS:
		if (ssl)
			return FILTER_PASSED;
		/* fallthrough */
	case SPB_PERMIT_AUTH:
		if (xmitstat.authname.len > 0)
			return FILTER_PASSED;
		break;
	case SPB_PERMIT_ESMTP:
		if (xmitstat.esmtp)
			return FILTER_PASSED;
		break;
	case SPB_REJECT_ALL:
		break;
	default: {
		const char *logval[] = {"unknown value for smtp_space_bug for address <", THISRCPT, ">", NULL};
		log_writen(LOG_ERR, logval);
		return FILTER_PASSED;
		}
	}

	log_writen(LOG_INFO, logmess);

	if (netwrite("500 5.5.2 command syntax error\r\n") != 0)
		return FILTER_ERROR;

	return FILTER_DENIED_WITH_MESSAGE;
}
