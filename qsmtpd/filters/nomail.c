#include <qsmtpd/userfilters.h>

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include "control.h"
#include "netio.h"
#include <qsmtpd/qsmtpd.h>

/**
 * The user does not want to receive any mail
 *
 * There are three possibilities how to work with the config file "nomail"
 * -if it is empty the mail will simply be rejected with a general error
 *  message
 * -if the message starts with "XYY X.Y.Y" (where Y is a decimal number
 *  and X is either 4 or 5) this will be used as the error code.
 * -if the message does not start with a SMTP rejection code it will be used
 *  with a rejection code of "550 5.7.1 ".
 */
enum filter_result
cb_nomail(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	size_t len;
	char *rejmsg;
	int fd;
	int i;
	int codebeg;		/* message begins with reject code */
	const char *netmsg[] = { "550 5.7.1 ", NULL, NULL };

	fd = getfile(ds, "nomail", t, 0);
	if (fd == -1)
		return (errno != ENOENT) ? FILTER_ERROR : FILTER_PASSED;

	*logmsg = "nomail";

	len = loadonelinerfd(fd, &rejmsg);
	if (len == (size_t)-1)
		return (errno != ENOENT) ? FILTER_ERROR : FILTER_DENIED_UNSPECIFIC;

	codebeg = (len > 10);

	for (i = 0; (i < 10) && codebeg; i++) {
		/* check that the beginning of the message is a valid return and
		 * enhanced status code, i.e. it matches:
		 * "([45])[0-9][0-9] ([45])\.[0-9]\.[0-9] " and the \1 == \2 */
		switch (i) {
		case 0:
			codebeg = ((rejmsg[0] == '4') ||
					(rejmsg[0] == '5'));
			break;
		case 3:
		case 9:
			codebeg = (rejmsg[i] == ' ');
			break;
		case 4: codebeg = (rejmsg[4] == rejmsg[0]);
			break;
		case 5:
		case 7:
			codebeg = (rejmsg[i] == '.');
			break;
		default:
			codebeg = isdigit(rejmsg[i]);
			break;
		}
	}

	netmsg[1] = rejmsg;
	/* if codebeg do not add the generic error code */
	i = net_writen(netmsg + !!codebeg);

	free(rejmsg);

	return (i != 0) ? FILTER_ERROR : FILTER_DENIED_WITH_MESSAGE;
}
