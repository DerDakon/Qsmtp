#include "usercallback.h"
#include "qsmtpd.h"

int
cb_whitelistauth(const struct userconf *ds, char **logmsg __attribute__ ((unused)), int *t)
{
	if (getsettingglobal(ds, "whitelistauth", t) <= 0)
		return 0;

	return (xmitstat.authname.len || xmitstat.tlsclient) ? 5 : 0;
}
