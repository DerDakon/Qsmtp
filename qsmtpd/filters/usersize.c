#include "usercallback.h"
#include "qsmtpd.h"
#include "netio.h"

int
cb_usersize(const struct userconf *ds, char **logmsg, int *t)
{
	long usize;
	int rc;

	if ((usize = getsetting(ds, "usersize", t)) <= 0)
		return 0;

	if (xmitstat.thisbytes <= (unsigned long) usize)
		return 0;

	if ((rc = netwrite("552 Requested mail action aborted: exceeded storage allocation")))
		return rc;
	*logmsg = "message too big";
	return 1;
}
