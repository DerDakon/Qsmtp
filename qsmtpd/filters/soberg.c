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
enum filter_result
cb_soberg(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	char *at;		/* '@' in the mailfrom */
	unsigned int userl;	/* strlen of the localpart */

	if (!xmitstat.mailfrom.len)
		return FILTER_PASSED;
	if (getsettingglobal(ds, "block_SoberG", t) <= 0)
		return FILTER_PASSED;

	/* this can't fail, either mailfrom.len is 0 or there is an '@' and at least one '.',
	 * addrsyntax() checks this before */
	at = strchr(xmitstat.mailfrom.s, '@');

	userl = at - xmitstat.mailfrom.s;
	if (strncasecmp(HELOSTR, xmitstat.mailfrom.s, userl))
		return FILTER_PASSED;
	if (strcasecmp(HELOSTR + userl, strrchr(xmitstat.mailfrom.s, '.')))
		return FILTER_PASSED;

	*logmsg = "SoberG suspect";
	if (netwrite("550 5.7.1 mail looks like SoberG worm\r\n") != 0)
		return FILTER_ERROR;
	else
		return FILTER_DENIED_WITH_MESSAGE;
}
