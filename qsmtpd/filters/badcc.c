/** \file badcc.c
 \brief reject multiple recipients mail if specific other recipients are given
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

/*
 * Bad CC: check the list of recipient addresses if there is someone were no CC makes sense
 *
 * Why this is useful: think of having one mail address per usegroup, sending a mail to more than one
 * at the same time is a very clear sign of a spam run.  To poison the mail address database we will
 * reply with "user unknown".
 *
 * There are three types entries in badmailfrom file:
 * 1) complete mail addresses: entire recipient address must match this one
 * 2) @domain: other recipients domain must match string, "@aol.com" would block "foo@aol.com" but not "foo@bar.aol.com"
 * 3) no '@' at all: block everything from this domain and subdomains, the character in recipients address before the match
 *    must be '.' or '@' so "aol.com" would reject "foo@aol.com" and "foo@bar.aol.com" but not "foo@no-aol.com"
 */
int
cb_badcc(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	char **a;		/* array of domains and/or mailaddresses to block */
	int rc;			/* return code */
	struct recip *np;	/* current recipient to check */

	/* if there is only one recipient we don't need to check for CC addresses */
	if (!head.tqh_first->entries.tqe_next)
		return 0;

	*t = userconf_get_buffer(ds, "badcc", &a, checkaddr, 1);
	if (((int)*t) < 0) {
		errno = -*t;
		return -1;
	} else if (*t == CONFIG_NONE) {
		return 0;
	}

	rc = 0;
	/* look through the list of recipients but ignore the current one */
	for (np = head.tqh_first; (np != NULL) && (rc == 0); np = np->entries.tqe_next) {
		char *at = strchr(np->to.s, '@');
		unsigned int i = 0;

		if (np == thisrecip)
			continue;

		while (a[i]) {
			if (*a[i] == '@') {
				if (at && !strcasecmp(a[i], at)) {
					rc = 2;
					break;
				}
			} else if (!strchr(a[i],'@')) {
				size_t k = strlen(a[i]);

				if (k < np->to.len) {
					char *c = np->to.s + (np->to.len - k);

					/* compare a[i] with the last k bytes of recipient address */
					if (!strcasecmp(c, a[i]) && ((*(c - 1) == '.') || (*(c - 1) == '@'))) {
						rc = 2;
						break;
					}
				}
			} else if (!strcasecmp(a[i], np->to.s)) {
				rc = 2;
				break;
			}

			i++;
		}
	}
	free(a);

	if (rc > 0)
		*logmsg = "bad CC";

	return rc;
}
