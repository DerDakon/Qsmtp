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

static int
lookupipbl(int fd)
{
	int i;
	char *a;		/* buffer to read file into */

	if ( ( i = lloadfilefd(fd, &a, 0) ) < 0 )
		return i;
	
	if (IN6_IS_ADDR_V4MAPPED(xmitstat.sremoteip.s6_addr)) {
		i = check_ip4(&(xmitstat.sremoteip), a, i);
	} else {
		i = check_ip6(&(xmitstat.sremoteip), a, i);
	}
	free(a);
	return i;
}

int
cb_ipbl(const struct userconf *ds, char **logmsg __attribute__ ((unused)), int *t)
{
	int i;			/* counter of the array position */
	int rc;			/* return code */
	int fd;			/* file descriptor of the policy file */
	const char *fnb;	/* filename of the blacklist file */
	const char *fnw;	/* filename of the whitelist file */
	const char *tmperr = "4.3.0 temporary policy error\r\n";
				/* error message announced on malformed file */

	if (IN6_IS_ADDR_V4MAPPED(xmitstat.sremoteip.s6_addr)) {
		fnb = "ipbl";
		fnw = "ipwl";
	} else {
		fnb = "ipblv6";
		fnw = "ipwlv6";
	}

	if ( (fd = getfileglobal(ds, fnb, t)) < 0)
		return (errno == ENOENT) ? 0 : -1;

	if ((i = lookupipbl(fd)) < 0)
		return i;
	if (i > 0) {
		int u;

		if ( (fd = getfile(ds, fnw, &u)) < 0) {
			if (errno != ENOENT)
				return -1;
			i = 0;
		} else {
			if ( (i = lookupipbl(fd)) < 0)
				return i;
		}
		if (i > 0) {
			logwhitelisted("ipbl", *t, u);
			rc = 0;
		} else if (!i) {
			*logmsg = "ipbl";
			rc = 2;
		} else {
			const char *logmess[] = {"bad input data in ", blocktype[u],
						"ipwl file for address <", THISRCPT, ">", NULL};
			log_writen(LOG_ERR, logmess);
			if (netwrite(tmperr))
				return -1;
			rc = 0;
		}
	} else if (!i) {
		rc = 0;
	} else {
		const char *logmess[] = {"bad input data in ", blocktype[*t],
					"ipbl file for address <", THISRCPT, ">", NULL};

		log_writen(LOG_ERR, logmess);
		if (netwrite(tmperr))
			return -1;
		rc = 0;
	}
	return rc;
}
