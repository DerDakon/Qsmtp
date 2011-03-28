/** \file check2822.c
 \brief check RfC2822 syntax of mail body
 */
#include "userfilters.h"
#include "qsmtpd.h"

int
cb_check2822(const struct userconf *ds, const char **logmsg __attribute__ ((unused)), int *t)
{
	/* This one is a bit special: it does not check the message for something
	 * itself, it just loads the configuration if smtp_data should check the
	 * message. If one of the recipients does not want this check the message
	 * will not be checked. We also always return 0, we do not check the message
	 * so we can't return anything else.  */

	/* if one user denied this check we don't need to check any more:
	 * the check is disabled */
	if (!xmitstat.check2822)
		return 0;

	if (!getsettingglobal(ds, "check_strict_rfc2822", t)) {
		/* no setting: the user has to explicitely enable this check so
		 * we disable the check and can stop here */
		xmitstat.check2822 = 0;
		return 0;
	}

	/* check2822 can be 2 (uninitialized) or 1 (all want it) here, in both cases we set it to 1 */
	xmitstat.check2822 = 1;
	return 0;
}
