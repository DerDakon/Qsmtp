#include <qsmtpd/userfilters.h>
#include <qsmtpd/qsmtpd.h>
#include "netio.h"

int
cb_usersize(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	long usize;
	int rc;

	if ((usize = getsetting(ds, "usersize", t)) <= 0)
		return 0;

	if (xmitstat.thisbytes <= (unsigned long) usize)
		return 0;

	if ((rc = netwrite("552 5.2.3 Requested mail action aborted: exceeded storage allocation\r\n")))
		return rc;
	*logmsg = "message too big";
	return 1;
}
