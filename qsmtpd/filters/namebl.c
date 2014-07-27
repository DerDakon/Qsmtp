#include <qsmtpd/userfilters.h>

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

int
cb_namebl(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	char **a;		/* array of blacklists to check */
	int i = 0;		/* counter of the array position */
	int rc = 0;		/* return code */
	char *txt = NULL;	/* TXT record of the rbl entry */
	const char *netmsg[] = {"501 5.7.1 message rejected, you are listed in ",
				NULL, NULL, NULL, NULL};
	const char *logmess[] = {"rejected message to <", THISRCPT, "> from <", MAILFROM,
				"> from IP [", xmitstat.remoteip, "] {listed in ", NULL, " from ",
				blocktype[*t], " namebl}", NULL};
	int flagtemp = 0;	/* true at least one list failed with temporary error */
	char *fromdomain;

	if (!xmitstat.mailfrom.len)
		return 0;

	*t = userconf_get_buffer(ds, "namebl", &a, domainvalid, 1);
	if (((int)*t) < 0) {
		errno = -*t;
		return -1;
	} else if (*t == CONFIG_NONE) {
		return 0;
	}

	fromdomain = strchr(xmitstat.mailfrom.s, '@') + 1;

	while (a[i] && (rc <= 0)) {
		char *d = fromdomain;
		size_t alen = strlen(a[i]) + 1;

		while (d && (rc <= 0)) {
			size_t dlen = strlen(d);
			char blname[256];

			if (dlen + alen < 256) {
				memcpy(blname, d, dlen);
				blname[dlen++] = '.';
				memcpy(blname + dlen, a[i], alen);

				rc = ask_dnsa(blname, NULL);
				switch (rc) {
				case DNS_ERROR_LOCAL:
					goto out;
				case DNS_ERROR_TEMP:
					flagtemp = 1;
				default:
					/* if there is any error here we just write the generic message to the client
					 * so that's no real problem for us */
					if (rc > 0)
						(void) dnstxt(&txt, blname);
					break;
				}
				/* ask_dnsa() returns >0 on success, that means we have a match */
			}
			if ( (d = strchr(d, '.')) )
				d++;
		}
		i++;
	}

	if (rc > 0) {
		logmess[7] = a[--i];
		log_writen(LOG_INFO, logmess);
		netmsg[1] = a[i];
		if (txt) {
			netmsg[2] = ", message: ";
			netmsg[3] = txt;
		}
		if (! (rc = net_writen(netmsg)) )
			rc = 1;
	} else if (flagtemp) {
		*logmsg = "temporary DNS error on RBL lookup";
		rc = 4;
	} else {
		rc = 0;
	}
out:
	free(a);
	free(txt);
	return rc;
}
