#include <qsmtpd/userfilters.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "netio.h"
#include <qsmtpd/qsmtpd.h>

/**
 * This checks if the combination of "MAIL FROM:" and "HELO" looks like SoberG
 *
 * SoberG's MAIL FROM: foo@bar.com would lead to HELO foo.com
 */
int
cb_soberg(const struct userconf *ds, const char **logmsg, int *t)
{
	int rc = 0;		/* return code */
	char *at;		/* '@' in the mailfrom */
	unsigned int userl;	/* strlen of the localpart */

	if (!xmitstat.mailfrom.len)
		return 0;
	if (getsettingglobal(ds, "block_SoberG", t) <= 0)
		return 0;

	/* this can't fail, either mailfrom.len is 0 or there is an '@' and at least one '.',
	 * addrsyntax() checks this before */
	at = strchr(xmitstat.mailfrom.s, '@');

	userl = at - xmitstat.mailfrom.s;
	if (strncasecmp(HELOSTR, xmitstat.mailfrom.s, userl))
		return 0;
	if (strcasecmp(HELOSTR + userl, strrchr(xmitstat.mailfrom.s, '.')))
		return 0;

	rc = netwrite("550 5.7.1 mail looks like SoberG worm\r\n");
	*logmsg = "SoberG suspect";
	return rc ? rc : 1;
}
