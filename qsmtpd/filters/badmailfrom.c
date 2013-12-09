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

static int
lookupbmf(char *at, char **a)
{
	unsigned int i = 0;
	int rc = 0;

	if (!a)
		return rc;

	while (a[i]) {
		if (*a[i] == '@') {
			if (at && !strcasecmp(a[i], at)) {
				rc = 2;
				break;
			}
		} else if (!strchr(a[i],'@')) {
			size_t k = strlen(a[i]);

			if (k < xmitstat.mailfrom.len) {
				char *c = xmitstat.mailfrom.s + (xmitstat.mailfrom.len - k);

				/* compare a[i] with the last k bytes of xmitstat.mailfrom.s */
				if (!strcasecmp(c, a[i])) {
					if ((*a[i] == '.') || (*(c - 1) == '.') || (*(c - 1) == '@')) {
						rc = 2;
						break;
					}
				}
			}
		} else if (!strcasecmp(a[i], xmitstat.mailfrom.s)) {
			rc = 2;
			break;
		}

		i++;
	}
	free(a);
	return rc;
}

int
cb_badmailfrom(const struct userconf *ds, const char **logmsg, int *t)
{
	int u;		/* if it is the user or domain policy */
	char *b;	/* buffer to read file into */
	char **a;	/* array of domains and/or mailaddresses to block */
	int rc = 0;	/* return code */
	int fd;		/* file descriptor of the policy file */
	char *at;

	if (!xmitstat.mailfrom.len)
		return 0;

	if ( (fd = getfileglobal(ds, "badmailfrom", t)) < 0)
		return (errno != ENOENT) ? fd : 0;

	/* don't check syntax of entries here: there might be things like ".cn" and so on that would fail the test */
	if ( (rc = loadlistfd(fd, &b, &a, NULL)) < 0)
		return rc;

	at = strchr(xmitstat.mailfrom.s, '@');
	rc = lookupbmf(at, a);
	free(b);
	if (!rc)
		return rc;

	*logmsg = "bad mail from";
	if ( (fd = getfileglobal(ds, "goodmailfrom", &u)) < 0) {
		if (errno != ENOENT)
			return fd;
	} else {
		if (loadlistfd(fd, &b, &a, checkaddr) < 0)
			return -1;
		if (lookupbmf(at, a)) {
			logwhitelisted(*logmsg, *t, u);
			rc = 0;
		}
		free(b);
	}
	return rc;
}
