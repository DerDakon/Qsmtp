#include <qsmtpd/userfilters.h>

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <qsmtpd/antispam.h>
#include "control.h"
#include "libowfatconn.h"
#include "log.h"
#include "netio.h"
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>

enum filter_result
cb_namebl(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	char **a;		/* array of blacklists to check */
	int i = 0;		/* counter of the array position */
	enum filter_result rc = FILTER_PASSED;	/* return code */
	char *txt = NULL;	/* TXT record of the rbl entry */
	const char *netmsg[] = {"501 5.7.1 message rejected, you are listed in ",
				NULL, NULL, NULL, NULL};
	const char *logmess[] = {"rejected message to <", THISRCPT, "> from <", MAILFROM,
				"> from IP [", xmitstat.remoteip, "] {listed in ", NULL, " from ",
				blocktype[*t], " namebl}", NULL};
	int flagtemp = 0;	/* true at least one list failed with temporary error */
	char *fromdomain;

	if (!xmitstat.mailfrom.len)
		return FILTER_PASSED;

	*t = userconf_get_buffer(ds, "namebl", &a, domainvalid, 1);
	if (((int)*t) < 0) {
		errno = -*t;
		return FILTER_ERROR;
	} else if (*t == CONFIG_NONE) {
		return FILTER_PASSED;
	}

	fromdomain = strchr(xmitstat.mailfrom.s, '@') + 1;

	while (a[i] && (rc == FILTER_PASSED)) {
		char *d = fromdomain;
		size_t alen = strlen(a[i]) + 1;

		while ((d != NULL) && (rc == FILTER_PASSED)) {
			size_t dlen = strlen(d);
			char blname[256];		/* maximum length of a valid DNS domain name + \0 */

			if (dlen + alen < sizeof(blname)) {
				int k;

				memcpy(blname, d, dlen);
				blname[dlen++] = '.';
				/* This is no overrun as alen already includes the terminating
				 * '\0', and the size was checked for being smaller than the
				 * buffer length before. */
				memcpy(blname + dlen, a[i], alen);

				k = ask_dnsa(blname, NULL);
				switch (k) {
				case DNS_ERROR_LOCAL:
					rc = FILTER_ERROR;
					break;
				case DNS_ERROR_TEMP:
					flagtemp = 1;
					break;
				case 0:
					/* no match, keep checking */
					break;
				case DNS_ERROR_PERM:
					/* invalid bl entry, ignore */
					break;
				default:
					/* ask_dnsa() returns >0 on success, that means we have a match */
					assert(k > 0);

					/* if there is any error here we just write the generic
					 * message to the client so that's no real problem for us */
					(void) dnstxt(&txt, blname);
					rc = FILTER_DENIED_UNSPECIFIC;
					break;
				}
			}
			d = strchr(d, '.');
			if (d != NULL)
				d++;
		}
		i++;
	}

	assert(rc != FILTER_WHITELISTED);
	if (filter_denied(rc)) {
		logmess[7] = a[--i];
		log_writen(LOG_INFO, logmess);
		netmsg[1] = a[i];
		if (txt) {
			netmsg[2] = ", message: ";
			netmsg[3] = txt;
		}
		if (net_writen(netmsg) != 0)
			rc = FILTER_ERROR;
		else
			rc = FILTER_DENIED_WITH_MESSAGE;
	} else if (rc == FILTER_ERROR) {
		/* just go on */
	} else if (flagtemp) {
		*logmsg = "temporary DNS error on RBL lookup";
		rc = FILTER_DENIED_TEMPORARY;
	} else {
		rc = FILTER_PASSED;
	}

	free(a);
	free(txt);
	return rc;
}
