#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include "antispam.h"
#include "usercallback.h"
#include "control.h"
#include "dns.h"
#include "log.h"
#include "netio.h"
#include "qsmtpd.h"

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
cb_badcc(const struct userconf *ds, char **logmsg, int *t)
{
	char *b;		/* buffer to read file into */
	char **a;		/* array of domains and/or mailaddresses to block */
	int rc;			/* return code */
	int fd;			/* file descriptor of the policy file */
	struct recip *np;	/* current recipient to check */

	/* if there is only one recipient we don't need to check for CC addresses */
	if (!head.tqh_first->entries.tqe_next)
		return 0;

	if ( (fd = getfile(ds, "badcc", t)) < 0)
		return (errno == ENOENT) ? 0 : -1;

	if ( ( rc = loadlistfd(fd, &b, &a, checkaddr, 1) ) < 0 )
		return rc;

	*logmsg = "bad CC";

	/* look through the list of recipients but ignore the last one: this is the actual one */
	for (np = head.tqh_first; np != thisrecip; np = np->entries.tqe_next) {
		char *at = strchr(np->to.s, '@');
		unsigned int i = 0;

		while (a[i]) {
			if (*a[i] == '@') {
				if (at && !strcasecmp(a[i], at)) {
					rc = 2;
					break;
				}
			} else if (!strchr(a[i],'@')) {
				unsigned int k = strlen(a[i]);
	
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
		if (rc)
			break;
	}
	free(a);
	free(b);

	return rc;
}
