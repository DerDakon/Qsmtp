#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "antispam.h"
#include "usercallback.h"
#include "control.h"
#include "dns.h"
#include "log.h"
#include "qsmtpd.h"

int
cb_forceesmtp(const struct userconf *ds, char **logmsg, int *t)
{
	char *b;		/* buffer to read file into */
	char **a;		/* array of domains and/or mailaddresses to block */
	int i;			/* counter of the array position */
	int rc;			/* return code */
	int fd;			/* file descriptor of the policy file */
	const char *fnb;	/* filename of the blacklist file */
	char *txt = NULL;	/* TXT record of the rbl entry */

	if (xmitstat.esmtp)
		return 0;

	if (xmitstat.ipv4conn) {
		fnb = "forceesmtp";
	} else {
		fnb = "forceesmtpv6";
	}

	if ( (fd = getfileglobal(ds, fnb, t)) < 0)
		return (errno == ENOENT) ? 0 : -1;

	if ( ( rc = loadlistfd(fd, &b, &a, domainvalid, 0) ) < 0 )
		return rc;

	i = check_rbl(a, &txt);
	free(a);
	free(b);
	free(txt);
	if (i < 0) {
		if (errno) {
			if (errno == EAGAIN) {
				*logmsg = "temporary DNS error on RBL lookup";
				rc = 4;
			} else {
				rc = -1;
			}
		}
	} else {
		*logmsg = "ESMTP forced";
		rc = 2;
	}
	return rc;
}
