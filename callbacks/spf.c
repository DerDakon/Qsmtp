#include <string.h>
#include <syslog.h>
#include "control.h"
#include "antispam.h"
#include "usercallback.h"
#include "dns.h"
#include "log.h"
#include "qsmtpd.h"
#include "netio.h"

/* Values for spfpolicy:
 *
 * 1: temporary DNS errors will block mail temporary
 * 2: rejects mail if the SPF record says 'fail'
 * 3: rejects mail when the SPF record says 'softfail'
 * 4: rejects mail when the SPF record says 'neutral'
 * 5 (or more): rejects mail when no SPF records are found or they are syntactically invalid
 *
 * If the reverse lookup matches a line in "ignorespf" file the mail will be accepted even if it would normally fail.
 * Use this e.g. if you are forwarding a mail from another account without changing the envelope from.
 *
 * If there is a domain "spfstrict" all mails from this domains must be a valid mail forwarder of this domain, so
 * a mail with SPF_NEUTRAL and spfpolicy == 2 from this domain will be blocked if client is not in ignorespf
 */  
int
cb_spf(const struct userconf *ds, const char **logmsg, int *t)
{
	int u;			/* if it is the user or domain policy */
	int rc = 1;		/* return code */
	long p;			/* spf policy */

	if ((xmitstat.spf == SPF_PASS) || !xmitstat.mailfrom.len)
		return 0;

	p = getsettingglobal(ds, "spfpolicy", t);

	if (p <= 0)
		return 0;

	if (xmitstat.spf == SPF_TEMP_ERROR) {
		rc = 4;
		goto block;
	}
	if (p == 1)
		goto strict;
	if (xmitstat.spf == SPF_FAIL)
		goto block;
	if (p == 2)
		goto strict;
	if (xmitstat.spf == SPF_SOFTFAIL)
		goto block;
	if (p == 3)
		goto strict;
	if (xmitstat.spf == SPF_NEUTRAL)
		goto block;
strict:
	rc = finddomainmm(getfileglobal(ds, "spfstrict", t), strchr(xmitstat.mailfrom.s, '@') + 1);
	if (rc <= 0)
		return rc;
block:
	if (!xmitstat.remotehost.len)
		return 1;
	rc = finddomainmm(getfileglobal(ds, "ignorespf", &u), xmitstat.remotehost.s);
	if (!rc) {
		logwhitelisted("SPF", *t, u);
		return 0;
	} else if (rc < 0) {
		return rc;
	}
	if ((rc = netwrite("501 5.7.1 mail denied by SPF policy\r\n")))
		return rc;
	*logmsg = "SPF";
	return 1;
}
