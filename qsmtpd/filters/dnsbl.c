#include <qsmtpd/userfilters.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <qsmtpd/antispam.h>
#include "control.h"
#include "log.h"
#include "netio.h"
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>

enum filter_result
cb_dnsbl(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	char **a;		/* array of domains and/or mailaddresses to block */
	int i;			/* counter of the array position */
	enum filter_result rc = FILTER_PASSED;	/* return code */
	const char *fnb;	/* filename of the blacklist file */
	const char *fnw;	/* filename of the whitelist file */
	char *txt = NULL;	/* TXT record of the rbl entry */

	if (connection_is_ipv4()) {
		fnb = "dnsbl";
		fnw = "whitednsbl";
	} else {
		fnb = "dnsblv6";
		fnw = "whitednsblv6";
	}

	*t = userconf_get_buffer(ds, fnb, &a, domainvalid, userconf_global);
	if (((int)*t) < 0) {
		errno = -*t;
		return FILTER_ERROR;
	} else if (*t == CONFIG_NONE) {
		return FILTER_PASSED;
	}

	i = check_rbl(a, &txt);
	if (i >= 0) {
		int j, u;
		char **c;		/* same like **a, just for whitelist */

		u = userconf_get_buffer(ds, fnw, &c, domainvalid, userconf_none);
		if (u < 0) {
			errno = -u;
			j = -1;
		} else if (u == CONFIG_NONE) {
			j = -1;
			errno = 0;
		} else {
			j = check_rbl(c, NULL);
		}

		if (j >= 0) {
			const char *logmess[] = { "not rejected message to <", THISRCPT, "> from <", MAILFROM,
						"> from IP [", xmitstat.remoteip, "] {listed in ", a[i], " from ",
						blocktype[*t], " dnsbl, but whitelisted by ",
						c[i], " from ", blocktype[u], " whitelist}", NULL };
			log_writen(LOG_INFO, logmess);
			free(c);
		} else if (errno) {
			if (errno == EAGAIN) {
				*logmsg = "temporary DNS error on RBL lookup";
				rc = FILTER_DENIED_TEMPORARY;
			} else {
				rc = FILTER_ERROR;
			}
		} else {
			const char *netmsg[] = { "501 5.7.1 message rejected, you are listed in ",
						a[i], NULL, txt, NULL };
			const char *logmess[] = { "rejected message to <", THISRCPT, "> from <", MAILFROM,
						"> from IP [", xmitstat.remoteip, "] {listed in ", a[i], " from ",
						blocktype[*t], " dnsbl}", NULL };

			log_writen(LOG_INFO, logmess);
			if (txt)
				netmsg[2] = ", message: ";

			if (net_writen(netmsg) != 0)
				rc = FILTER_ERROR;
			else
				rc = FILTER_DENIED_WITH_MESSAGE;
		}
	} else if (errno) {
		if (errno == EAGAIN) {
			*logmsg = "temporary DNS error on RBL lookup";
			rc = FILTER_DENIED_TEMPORARY;
		} else {
			rc = FILTER_ERROR;
		}
	}

	free(a);
	free(txt);
	return rc;
}
