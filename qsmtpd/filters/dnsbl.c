#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include "antispam.h"
#include "userfilters.h"
#include "control.h"
#include "log.h"
#include "netio.h"
#include "qsmtpd.h"

int
cb_dnsbl(const struct userconf *ds, char **logmsg, int *t)
{
	char *b;		/* buffer to read file into */
	char **a;		/* array of domains and/or mailaddresses to block */
	int i;			/* counter of the array position */
	int rc;			/* return code */
	int fd;			/* file descriptor of the policy file */
	const char *fnb;	/* filename of the blacklist file */
	const char *fnw;	/* filename of the whitelist file */
	char *txt = NULL;	/* TXT record of the rbl entry */

	if (xmitstat.ipv4conn) {
		fnb = "dnsbl";
		fnw = "whitednsbl";
	} else {
		fnb = "dnsblv6";
		fnw = "whitednsblv6";
	}

	if ( (fd = getfileglobal(ds, fnb, t)) < 0)
		return (errno == ENOENT) ? 0 : -1;

	if ( (rc = loadlistfd(fd, &b, &a, domainvalid)) < 0)
		return rc;

	i = check_rbl(a, &txt);
	if (i >= 0) {
		int j, u;
		char *d, **c;		/* same like *a and **b, just for whitelist */

		if ( (fd = getfile(ds, fnw, &u)) < 0) {
			if (errno != ENOENT) {
				free(a);
				free(b);
				free(txt);
				return fd;
			}
			j = fd;
			errno = 0;
		} else {
			char *wtxt;

			if ( (rc = loadlistfd(fd, &d, &c, domainvalid)) < 0) {
				free(a);
				free(b);
				free(txt);
				return rc;
			}

			j = check_rbl(c, &wtxt);
			free(wtxt);
		}
		if (j >= 0) {
			const char *logmess[] = {"not rejected message to <", THISRCPT, "> from <", MAILFROM,
						"> from IP [", xmitstat.remoteip, "] {listed in ", a[i], " from ",
						blocktype[*t], " dnsbl, but whitelisted by ",
						c[i], " from ", blocktype[u], " whitelist}", NULL};
			log_writen(LOG_INFO, logmess);
		} else {
			if (errno) {
				if (errno == EAGAIN) {
					*logmsg = "temporary DNS error on RBL lookup";
					rc = 4;
				} else {
					rc = j;
				}
			} else {
				const char *netmsg[] = {"501 5.7.1 message rejected, you are listed in ",
							a[i], NULL, NULL, NULL};
				const char *logmess[] = {"rejected message to <", THISRCPT, "> from <", MAILFROM,
							"> from IP [", xmitstat.remoteip, "] {listed in ", a[i], " from ",
							blocktype[*t], " dnsbl}", NULL};

				log_writen(LOG_INFO, logmess);
				if (txt) {
					netmsg[2] = ", message: ";
					netmsg[3] = txt;
				}
				if ( ! (rc = net_writen(netmsg)) )
					rc = 1;
			}
		}
	} else {
		if (errno) {
			if (errno == EAGAIN) {
				*logmsg = "temporary DNS error on RBL lookup";
				rc = 4;
			} else {
				rc = -1;
			}
		}
	}
	free(a);
	free(b);
	free(txt);
	return rc;
}
