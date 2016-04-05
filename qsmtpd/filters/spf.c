/** \file qsmtpd/filters/spf.c
 \brief reject mail based on SPF policy
 */
#include <qsmtpd/userfilters.h>

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include "control.h"
#include <qsmtpd/antispam.h>
#include "log.h"
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>
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
 * If the reverse lookup matches a line in "spfignore" file the mail will be accepted even if it would normally fail.
 * Use this e.g. if you are forwarding a mail from another account without changing the envelope from.
 *
 * If there is a domain "spfstrict" all mails from this domains must be a valid mail forwarder of this domain, so
 * a mail with SPF_NEUTRAL and spfpolicy == 2 from this domain will be blocked if client is not in spfignore.
 *
 * If no SPF record is found in DNS then the locally given sources will be searched for SPF records. This might set
 * a secondary SPF record for domains often abused for phishing.
 */
enum filter_result
cb_spf(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	enum filter_result r = FILTER_DENIED_WITH_MESSAGE;	/* return code */
	long p;				/* spf policy */
	const char *fromdomain = NULL;	/* pointer to the beginning of the domain in xmitstat.mailfrom.s */
	int spfs = xmitstat.spf;	/* the spf status to check, either global or local one */
	enum config_domain tmpt;
	char *exps = xmitstat.spfexp;	/* SPF explanation string */

	if ((spfs == SPF_PASS) || (spfs == SPF_IGNORE))
		return FILTER_PASSED;

	p = getsettingglobal(ds, "spfpolicy", t);

	if (p <= 0)
		return FILTER_PASSED;

	*logmsg = NULL;

	if (xmitstat.remotehost.len) {
		int u;				/* if it is the user or domain policy */

		u = userconf_find_domain(ds, "spfignore", xmitstat.remotehost.s, 1);
		if (u < 0) {
			errno = -u;
			return FILTER_ERROR;
		} else if (u != CONFIG_NONE) {
			logwhitelisted("SPF", *t, u);
			return FILTER_PASSED;
		}
	}

/* there is no official SPF entry: go and check if someone else provided one, e.g. rspf.rhsbl.docsnyder.de. */
	if (spfs == SPF_NONE) {
		char **a;
		char spfname[DOMAINNAME_MAX + 1];
		int v = 0;
		size_t fromlen;	/* strlen(fromdomain) */
		int olderror = SPF_NONE;

		assert(exps == NULL);

		*t = userconf_get_buffer(ds, "rspf", &a, domainvalid, userconf_global);
		if (((int)*t) < 0) {
			errno = -*t;
			return FILTER_ERROR;
		} else if (*t == CONFIG_NONE) {
			return FILTER_PASSED;
		}

		if (xmitstat.mailfrom.len) {
			fromdomain = strchr(xmitstat.mailfrom.s, '@') + 1;
			fromlen = xmitstat.mailfrom.len - (fromdomain - xmitstat.mailfrom.s);
		} else {
			fromdomain = HELOSTR;
			fromlen = HELOLEN;
		}
		memcpy(spfname, fromdomain, fromlen);
		spfname[fromlen++] = '.';

		/* First match wins. */
		while (a[v] && ((spfs == SPF_NONE) || (spfs == SPF_TEMPERROR) || (spfs == SPF_DNS_HARD_ERROR) || (spfs == SPF_PERMERROR))) {
			memcpy(spfname + fromlen, a[v], strlen(a[v]) + 1);
			if ((spfs != SPF_NONE) && (olderror == SPF_NONE))
				olderror = spfs;

			/* In case you have an SPF_PERMERROR rSPF and afterwards a different
			 * error code the information how the record was malformed is lost. */
			free(exps);
			spfs = check_host(spfname);
			/* check_host() will record the exp= modifier result in xmitstat,
			 * make sure it does not leak to another user */
			exps = xmitstat.spfexp;
			xmitstat.spfexp = NULL;
			v++;
		}
		free(a);

		switch (spfs) {
		default:
			if (spfs >= 0) {
				if (spfs == SPF_NONE)
					spfs = olderror;
				*logmsg = "rSPF";
				break;
			}
			/* fallthrough */
		case SPF_PASS: /* no match in rSPF filters */
			free(exps);
			return FILTER_PASSED;
		case SPF_DNS_HARD_ERROR: /* last rSPF filter is not reachable */
			spfs = SPF_NONE;
			break;
		}
	}

	if (spfs == SPF_TEMPERROR) {
		r = FILTER_DENIED_TEMPORARY;
		goto block;
	}
	if ((p == 1) && (spfs == SPF_SOFTFAIL))
		goto strict;
	if (SPF_IS_FAILURE(spfs))
		goto block;
	if (p == 2)
		goto strict;
	if (spfs == SPF_DNS_HARD_ERROR) {
		*logmsg = "bad SPF";
		if (netwrite("550 5.5.2 syntax error in SPF record\r\n") != 0)
			return FILTER_ERROR;
		else
			return FILTER_DENIED_WITH_MESSAGE;
	}
	if (p == 3)
		goto strict;
	if (spfs == SPF_SOFTFAIL)
		goto block;
	if (p == 4)
		goto strict;
	if (spfs == SPF_NEUTRAL)
		goto block;
	assert(spfs == SPF_NONE);
	if (p != 5)
		goto block;
strict:
	if (!fromdomain) {
		if (xmitstat.mailfrom.len) {
			fromdomain = strchr(xmitstat.mailfrom.s, '@') + 1;
		} else {
			fromdomain = HELOSTR;
		}
	}
	*t = userconf_find_domain(ds, "spfstrict", fromdomain, 1);
	if (((int)*t) < 0) {
		errno = -*t;
		return FILTER_ERROR;
	} else if (*t == CONFIG_NONE) {
		return FILTER_PASSED;
	}
block:
	if (r == FILTER_DENIED_WITH_MESSAGE) {
		const char *netmsg[] = {"550 5.7.1 mail denied by SPF policy", ", SPF record says: ",
				exps, NULL};
		int n;

		/* if there was a hard DNS error ignore the spfexp string, it may be inappropriate */
		if ((exps == NULL) || (spfs == SPF_DNS_HARD_ERROR))
			netmsg[1] = NULL;

		n = net_writen(netmsg);
		/* only free the string if is was set from rSPF */
		if (xmitstat.spfexp == NULL)
			free(exps);
		if (n != 0)
			return FILTER_ERROR;
	} else if ((r == FILTER_DENIED_TEMPORARY) && (getsetting(ds, "fail_hard_on_temp", &tmpt) <= 0)) {
		*logmsg = "temp SPF";
		if (xmitstat.spfexp == NULL)
			free(exps);
		if (netwrite("451 4.4.3 temporary error when checking the SPF policy\r\n") != 0)
			return FILTER_ERROR;
		return FILTER_DENIED_WITH_MESSAGE;
	} else {
		if (xmitstat.spfexp == NULL)
			free(exps);
	}

	if (!*logmsg)
		*logmsg = "SPF";
	return r;
}
