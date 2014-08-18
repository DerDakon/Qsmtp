/** \file badmailfrom.c
 \brief reject mail based on envelope from
 */
#include <qsmtpd/userfilters.h>

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <qsmtpd/addrparse.h>
#include "control.h"
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>
#include "log.h"

/* Bad "MAIL FROM": reject sender addresses or domains, case is ignored
 *
 * There are three types entries in badmailfrom file:
 * 1) complete mail addresses: entire from address must match this one
 * 2) @domain: from domain must match string, "@aol.com" would block "foo@aol.com" but not "foo@bar.aol.com"
 * 3) no '@' at all: block everything from this domain and subdomains, the character in MAIL FROM before the match
 *    must be '.' or '@' so "aol.com" would reject "foo@aol.com" and "foo@bar.aol.com" but not "foo@no-aol.com"
 * 4) beginning with '.': block everything ending with string, so ".aol.com" would block every subdomain of aol.com,
 *    but not aol.com itself
 */

static enum filter_result
lookupbmf(char *at, char **a)
{
	unsigned int i = 0;
	enum filter_result rc = FILTER_PASSED;

	if (!a)
		return rc;

	while (a[i]) {
		if (*a[i] == '@') {
			if (at && !strcasecmp(a[i], at)) {
				rc = FILTER_DENIED_UNSPECIFIC;
				break;
			}
		} else if (!strchr(a[i],'@')) {
			size_t k = strlen(a[i]);

			if (k < xmitstat.mailfrom.len) {
				const char *c = xmitstat.mailfrom.s + (xmitstat.mailfrom.len - k);

				/* compare a[i] with the last k bytes of xmitstat.mailfrom.s */
				if (!strcasecmp(c, a[i])) {
					if ((*a[i] == '.') || (*(c - 1) == '.') || (*(c - 1) == '@')) {
						rc = FILTER_DENIED_UNSPECIFIC;
						break;
					}
				}
			}
		} else if (!strcasecmp(a[i], xmitstat.mailfrom.s)) {
			rc = FILTER_DENIED_UNSPECIFIC;
			break;
		}

		i++;
	}
	free(a);
	return rc;
}

enum filter_result
cb_badmailfrom(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	int u;		/* if it is the user or domain policy */
	char **a;	/* array of domains and/or mailaddresses to block */
	enum filter_result rc = 0;	/* return code */
	char *at;

	if (!xmitstat.mailfrom.len)
		return FILTER_PASSED;

	/* don't check syntax of entries here: there might be things like ".cn" and so on that would fail the test */
	*t = userconf_get_buffer(ds, "badmailfrom", &a, NULL, 1);
	if (((int)*t) < 0) {
		errno = -*t;
		return FILTER_ERROR;
	} else if (*t == CONFIG_NONE) {
		return FILTER_PASSED;
	}

	at = strchr(xmitstat.mailfrom.s, '@');
	rc = lookupbmf(at, a);
	if (rc == FILTER_PASSED)
		return rc;

	*logmsg = "bad mail from";
	u = userconf_get_buffer(ds, "goodmailfrom", &a, checkaddr, 1);
	if (u < 0) {
		errno = -u;
		return FILTER_ERROR;
	} else if (u != CONFIG_NONE) {
		if (lookupbmf(at, a)) {
			logwhitelisted(*logmsg, *t, u);
			rc = FILTER_PASSED;
		}
	}
	return rc;
}
