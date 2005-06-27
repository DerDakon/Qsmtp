#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include "userfilters.h"
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
	long l;

	if (xmitstat.helostatus) {
		/* see dns.h for the meaning of helostatus */
		l = getsettingglobal(ds, "helovalid", t);
		if ((1 << xmitstat.helostatus) & l) {
			const char *badtypes[] = {"HELO is my name", "HELO is [my IP]", "HELO is syntactically invalid",
						"", "HELO is my IP", "", ""};
	
			/* just shut up compiler: logmsg will never be modified */
			*logmsg = (char *) badtypes[xmitstat.helostatus - 1];
			return 2;
		}
	}

	rc = finddomainfd(getfileglobal(ds, "badhelo", t), HELOSTR, 1);
	if (rc <= 0)
		return rc;

	*logmsg = "bad helo";
	return 2;
}
