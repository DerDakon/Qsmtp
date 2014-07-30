/** \file boolean.c
 \brief boolean reject decisions
 */
#include <qsmtpd/userfilters.h>

#include <qsmtpd/qsmtpd.h>
#include "tls.h"
#include "netio.h"
#include "log.h"

#include <syslog.h>

enum filter_result
cb_boolean(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	if (getsettingglobal(ds, "whitelistauth", t) > 0) {
		if (is_authenticated_client())
			return FILTER_WHITELISTED;
	}

	/* This rule violates RfC 3207, section 4:
	 *     A publicly-referenced SMTP server MUST NOT require use of the
	 *     STARTTLS extension in order to deliver mail locally.
	 * We offer it for paranoid users but don't use getsettingglobal here so
	 * it can't be turned on for everyone by accident (or stupid postmaster) */
	if (!ssl && (getsetting(ds, "forcestarttls", t) > 0)) {
		int rc = netwrite("501 5.7.1 recipient requires encrypted message transmission\r\n");
		*logmsg = "TLS required";
		return (rc != 0) ? FILTER_ERROR : FILTER_DENIED_WITH_MESSAGE;
	}

	/* This rule is very tricky, normally you want bounce messages.
	 * But if you are sure that there can't be any bounce messages (e.g. the address
	 * is only used on a website or as a usenet From or Reply-To address) this will
	 * block spamruns, joe-jobs and bounces from braindead virus scanners */
	if (!xmitstat.mailfrom.len && (getsetting(ds, "nobounce", t) > 0)) {
		const char *logmess[] = {"rejected message to <", THISRCPT, "> from IP [", xmitstat.remoteip,
					"] {no bounces allowed}", NULL};

		int rc = netwrite("550 5.7.1 address does not send mail, there can't be any bounces\r\n");
		log_writen(LOG_INFO, logmess);
		return (rc != 0) ? FILTER_ERROR : FILTER_DENIED_WITH_MESSAGE;
	}

	if ((getsetting(ds, "noapos", t) > 0) && xmitstat.mailfrom.len) {
		const char *at = strchr(xmitstat.mailfrom.s, '@');

		if (memchr(xmitstat.mailfrom.s, '\'', at - xmitstat.mailfrom.s)) {
			*logmsg = "apostroph in from";
			return FILTER_DENIED_UNSPECIFIC;
		}
	}

	return FILTER_PASSED;
}
