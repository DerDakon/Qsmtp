#include <syslog.h>
#include "usercallback.h"
#include "netio.h"
#include "qsmtpd.h"
#include "log.h"

int
cb_nobounce(const struct userconf *ds, char **logmsg __attribute__ ((unused)), int *t)
{
	int rc = 0;		/* return code */
	const char *logmess[] = {"rejected message to <", THISRCPT, "> from IP [", xmitstat.remoteip,
				"] {no bounces allowed}", NULL};

	if (xmitstat.mailfrom.len)
		return 0;
	/* This rule is very tricky, normally you want bounce messages.
	 * But if you are sure that there can't be any bounce messages (e.g. the address
	 * is only used on a website or as a usenet From or Reply-To address) this will
	 * block spamruns, joe-jobs and bounces from braindead virus scanners */
	if (!getsetting(ds, "nobounce", t))
		return 0;

	rc = netwrite("550 5.7.1 address does not send mail, there can't be any bounces\r\n");
	log_writen(LOG_INFO, logmess);
	return rc ? rc : 1;
}
