/** \file rcpt_filters.c
 \brief collection of all user filters for access by qsmtpd.c
 */
#include <qsmtpd/userfilters.h>

#include "log.h"
#include <syslog.h>

/* add all your filters here */

extern enum filter_result cb_nomail(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_boolean(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_badmailfrom(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_dnsbl(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_check2822(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_ipbl(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_badcc(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_fromdomain(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_smtpbugs(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_spf(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_soberg(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_helo(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_usersize(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_forceesmtp(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_namebl(const struct userconf *, const char **, enum config_domain *);
extern enum filter_result cb_wildcardns(const struct userconf *, const char **, enum config_domain *);
/*extern enum filter_result cb_postfix(const struct userconf *, const char **, enum config_domain *);*/

/** the user filters will be called in the order in this array */
rcpt_cb rcpt_cbs[] = {
/* offline checks first */
			cb_boolean,
			cb_nomail,
			cb_smtpbugs,
			cb_usersize,
			cb_soberg,
			cb_ipbl,
			cb_helo,
			cb_spf,
			cb_badmailfrom,
			cb_badcc,
			cb_fromdomain,
/* now online checks */
			cb_dnsbl,
			cb_forceesmtp,
			cb_namebl,
			cb_wildcardns,
/* this one is special: it will not block anything here so we need it only when mail is not blocked anyway */
			cb_check2822,
			NULL};

rcpt_cb late_cbs[] = {
			cb_badcc
};

/** string constants for the type of blocklists */
const char *blocktype[] = { NULL, "user", "domain", NULL, "global" };

/** write message to syslog that a otherwise rejected mail has been passed because of whitelisting
 *
 * \param reason reason of whitelisting
 * \param t which type of filter caused blacklisting
 * \param u which type of filter caused whitelisting
 */
void
logwhitelisted(const char *reason, const int t, const int u)
{
	const char *logmess[] = {"not rejected message to <", THISRCPT, "> from <",
				MAILFROM, "> from IP [", xmitstat.remoteip,
				"] {", reason, " blocked by ", blocktype[t],
				" policy, whitelisted by ", blocktype[u],
				" policy}", NULL};
	log_writen(LOG_INFO, logmess);
}
