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
	const char *helo;
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

	/* be careful: helostr is only set if it differs from the reverse lookup */
	if (xmitstat.helostr.len)
		helo = xmitstat.helostr.s;
	else
		helo = xmitstat.remotehost.s;

	rc = finddomainmm(getfileglobal(ds, "badhelo", t), helo);
	if (rc <= 0)
		return rc;

	*logmsg = "bad helo";
	return 2;
}
