#include <qsmtpd/userfilters.h>
#include <qsmtpd/qsmtpd.h>
#include "netio.h"

enum filter_result
cb_usersize(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	long usize;

	if ((usize = getsetting(ds, "usersize", t)) <= 0)
		return FILTER_PASSED;

	if (xmitstat.thisbytes <= (unsigned long) usize)
		return FILTER_PASSED;

	*logmsg = "message too big";
	if (netwrite("552 5.2.3 Requested mail action aborted: exceeded storage allocation\r\n") != 0)
		return FILTER_ERROR;
	else
		return FILTER_DENIED_WITH_MESSAGE;
}
