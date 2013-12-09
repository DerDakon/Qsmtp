/** \file boolean.c
 \brief boolean reject decisions
 */
#include <qsmtpd/userfilters.h>

#include <qsmtpd/qsmtpd.h>
#include "tls.h"
#include "netio.h"
#include "log.h"

#include <syslog.h>

int
cb_boolean(const struct userconf *ds, const char **logmsg, int *t)
{
	int rc;

	if (getsettingglobal(ds, "whitelistauth", t) > 0) {
		if (xmitstat.authname.len || xmitstat.tlsclient)
			return 5;
	}

	/* This rule violates RfC 3207, section 4:
	 *     A publicly-referenced SMTP server MUST NOT require use of the
	 *     STARTTLS extension in order to deliver mail locally.
	 * We offer it for paranoid users but don't use getsettingglobal here so
	 * it can't be turned on for everyone by accident (or stupid postmaster) */
	if (!ssl && (getsetting(ds, "forcestarttls", t) > 0)) {
		rc = netwrite("501 5.7.1 recipient requires encrypted message transmission\r\n");
		*logmsg = "TLS required";
		return rc ? rc : 1;
	}

	/* This rule is very tricky, normally you want bounce messages.
	 * But if you are sure that there can't be any bounce messages (e.g. the address
	 * is only used on a website or as a usenet From or Reply-To address) this will
	 * block spamruns, joe-jobs and bounces from braindead virus scanners */
	if (!xmitstat.mailfrom.len && (getsetting(ds, "nobounce", t) > 0)) {
		const char *logmess[] = {"rejected message to <", THISRCPT, "> from IP [", xmitstat.remoteip,
					"] {no bounces allowed}", NULL};

		rc = netwrite("550 5.7.1 address does not send mail, there can't be any bounces\r\n");
		log_writen(LOG_INFO, logmess);
		return rc ? rc : 1;
	}

	if ((getsetting(ds, "noapos", t) > 0) && xmitstat.mailfrom.len) {
		const char *at = strchr(xmitstat.mailfrom.s, '@');

		if (memchr(xmitstat.mailfrom.s, '\'', at - xmitstat.mailfrom.s)) {
			rc = netwrite("501 5.7.1 recipient does not like you\r\n");
			*logmsg = "apostroph in from";
			return rc ? rc : 1;
		}
	}

	return 0;
}
