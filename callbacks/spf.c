#include <string.h>
#include <syslog.h>
#include "control.h"
#include "antispam.h"
#include "usercallback.h"
#include "dns.h"
#include "log.h"
#include "qsmtpd.h"
#include "netio.h"

/* Values for spfpolicy:
 *
 * 1: temporary DNS errors will block mail temporary
 * 2: rejects mail if the SPF record says 'fail'
 * 3: rejects mail if the SPF record is syntactically invalid
 * 4: rejects mail when the SPF record says 'softfail'
 * 5: rejects mail when the SPF record says 'neutral'
 * 6: rejects mail when there is no SPF record
 *
 * If the reverse lookup matches a line in "ignorespf" file the mail will be accepted even if it would normally fail.
 * Use this e.g. if you are forwarding a mail from another account without changing the envelope from.
 *
 * If there is a domain "spfstrict" all mails from this domains must be a valid mail forwarder of this domain, so
 * a mail with SPF_NEUTRAL and spfpolicy == 2 from this domain will be blocked if client is not in ignorespf
 *
 * If no SPF record is found in DNS then the locally given sources will be searched for SPF records. This might set
 * a secondary SPF record for domains often abused for phishing.
 */
int
cb_spf(const struct userconf *ds, const char **logmsg, int *t)
{
	int r = 0, rc = 1;		/* return code */
	long p;				/* spf policy */
	char *fromdomain = NULL;	/* pointer to the beginning of the domain in xmitstat.mailfrom.s */
	int spfs = xmitstat.spf;	/* the spf status to check, either global or local one */

	if (spfs == SPF_PASS)
		return 0;

	p = getsettingglobal(ds, "spfpolicy", t);

	if (p <= 0)
		return 0;

/* there is no official SPF entry: go and check if someone else provided one, e.g. rspf.rhsbl.docsnyder.de. */
	if (spfs == SPF_NONE) {
		int v = 0, fd;
		char **a, *b, spfname[256];
		unsigned int fromlen;	/* strlen(fromdomain) */

		if ( (fd = getfileglobal(ds, "rspf", t)) < 0)
			return (errno == ENOENT) ? 0 : -1;

		if ( ( rc = loadlistfd(fd, &b, &a, domainvalid, 0) ) < 0 )
			return rc;

		fromdomain = strchr(xmitstat.mailfrom.s, '@') + 1;
		fromlen = xmitstat.mailfrom.len - (fromdomain - xmitstat.mailfrom.s);
		memcpy(spfname, fromdomain, fromlen);
		spfname[fromlen++] = '.';

		/* First match wins. */
		while (a[v] && (spfs >= 0) &&
					((spfs == SPF_NONE) || (spfs == SPF_TEMP_ERROR) || (spfs == SPF_HARD_ERROR) ||
					(spfs == SPF_FAIL_NONEX))) {
			memcpy(spfname + fromlen, a[v], strlen(a[v]) + 1);
			spfs = check_host(spfname);
			v++;
		}
		free(a);
		free(b);
		if ((spfs == SPF_PASS) || (spfs < 0)) {
			return 0;
		}
		if (spfs == SPF_HARD_ERROR) {
			spfs = SPF_NONE;
		} else {
			*logmsg = "rSPF";
		}
	}

	if (spfs == SPF_TEMP_ERROR) {
		r = 4;
		goto block;
	}
	if (p == 1)
		goto strict;
	if (SPF_FAIL(spfs))
		goto block;
	if (p == 2)
		goto strict;
	if (spfs == SPF_HARD_ERROR)
		goto block;
	if (p == 3)
		goto strict;
	if (spfs == SPF_SOFTFAIL)
		goto block;
	if (p == 4)
		goto strict;
	if (spfs == SPF_NEUTRAL)
		goto block;
/* spfs can only be SPF_NONE here */
	if (p != 5)
		goto block;
strict:
	if (!fromdomain) {
		fromdomain = strchr(xmitstat.mailfrom.s, '@') + 1;
	}
	rc = finddomainmm(getfileglobal(ds, "spfstrict", t), fromdomain);
	if (rc <= 0)
		return rc;
block:
	if (xmitstat.remotehost.len) {
		int u;				/* if it is the user or domain policy */

		rc = finddomainmm(getfileglobal(ds, "ignorespf", &u), xmitstat.remotehost.s);
		if (rc > 0) {
			logwhitelisted("SPF", *t, u);
			return 0;
		} else if (rc < 0) {
			return rc;
		}
	}
	if (xmitstat.spfexp) {
		const char *netmsg[] = {"501 5.7.1 ", xmitstat.spfexp, NULL};

		if ((rc = net_writen(netmsg)))
			return rc;
	} else {
		if ((rc = netwrite("501 5.7.1 mail denied by SPF policy\r\n")))
			return rc;
	}
	if (!*logmsg)
		*logmsg = "SPF";
	return r ? r : 1;
}
