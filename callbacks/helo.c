#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include "usercallback.h"
#include "control.h"
#include "qsmtpd.h"

/* Bad HELO: reject senders with HELOs you don't like
 *
 * There are two types entries in badhelo file:
 * 1) beginning with '.': helo is blocked if it ends with this string
 * 2) not beginning with '.': helo is blocked if it matches this string
 */

int
cb_helo(const struct userconf *ds, char **logmsg, int *t)
{
	int rc = 0;	/* return code */

	rc = finddomainmm(getfileglobal(ds, "badhelo", t), xmitstat.helostr.s);
	if (rc <= 0)
		return rc;

	*logmsg = "bad helo";
	return 2;
}
