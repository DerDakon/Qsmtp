#include <qsmtpd/userfilters.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include "control.h"
#include <qsmtpd/qsmtpd.h>

/* Bad HELO: reject senders with HELOs you don't like
 *
 * There are two types entries in badhelo file:
 * 1) beginning with '.': helo is blocked if it ends with this string
 * 2) not beginning with '.': helo is blocked if it matches this string
 */
int
cb_helo(const struct userconf *ds, const char **logmsg, int *t)
{
	int rc = 0;	/* return code */
	long l;

	if (xmitstat.helostatus) {
		/* see qdns.h for the meaning of helostatus */
		l = getsettingglobal(ds, "helovalid", t);
		if ((1 << xmitstat.helostatus) & l) {
			const char *badtypes[] = {"HELO is my name", "HELO is [my IP]", "HELO is syntactically invalid",
						"", "HELO is my IP", "", ""};

			*logmsg = badtypes[xmitstat.helostatus - 1];
			return 2;
		}
	}

	rc = finddomainfd(getfileglobal(ds, "badhelo", t), HELOSTR, 1);
	if (rc <= 0)
		return rc;

	*logmsg = "bad helo";
	return 2;
}
