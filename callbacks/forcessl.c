#include <errno.h>
#include <unistd.h>
#include "usercallback.h"
#include "netio.h"
#include "tls.h"

int
cb_forcessl(const struct userconf *ds, char **logmsg, int *t)
{
	int rc = 0;		/* return code */

	/* This rule violates RfC 3207, section 4:
	 *     A publicly-referenced SMTP server MUST NOT require use of the
	 *     STARTTLS extension in order to deliver mail locally.
	 * We offer it for paranoid users but don't use getfileglobal here so
	 * it can't be turned on for everyone by accident (or stupid postmaster) */
	if (!getsetting(ds, "forcestarttls", t))
		return 0;

	if (!ssl) {
		rc = net_write("501 5.7.1 recipient requires encrypted message");
		*logmsg = "TLS required";
		if (!rc)
			rc++;
	}
	return rc;
}
