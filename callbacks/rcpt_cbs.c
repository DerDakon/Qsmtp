#include <syslog.h>
#include "log.h"
#include "usercallback.h"

/* add all your user callbacks here */

extern int cb_badmailfrom(const struct userconf *, char **, int *);
extern int cb_dnsbl(const struct userconf *, char **, int *);
extern int cb_check2822(const struct userconf *, char **, int *);
extern int cb_forcessl(const struct userconf *, char **, int *);
extern int cb_whitelistauth(const struct userconf *, char **, int *);
extern int cb_ipbl(const struct userconf *, char **, int *);
extern int cb_badcc(const struct userconf *, char **, int *);
extern int cb_fromdomain(const struct userconf *, char **, int *);
extern int cb_spf(const struct userconf *, char **, int *);
extern int cb_soberg(const struct userconf *, char **, int *);
extern int cb_nobounce(const struct userconf *, char **, int *);
extern int cb_helo(const struct userconf *, char **, int *);
extern int cb_usersize(const struct userconf *, char **, int *);

/* the callbacks will be called in the order in this array */

/* offline checks first */
rcpt_cb rcpt_cbs[] = {	cb_whitelistauth,
			cb_usersize,
			cb_soberg,
			cb_nobounce,
			cb_forcessl,
			cb_fromdomain,
			cb_ipbl,
			cb_helo,
			cb_spf,
			cb_badmailfrom,
			cb_badcc,
/* now online checks */
			cb_dnsbl,
/* this one is special: it will not block anything here so we need it only when mail is not blocked anyway */
			cb_check2822,
			NULL};

/* string constants for the type of blocklists */

const char *blocktype[] = {"user", "domain", "global"};

void
logwhitelisted(const char *reason, const int t, const int u)
{
	const char *logmess[] = {"not rejected message to <", THISRCPT, "> from <",
				xmitstat.mailfrom.s, "> from IP [", xmitstat.remoteip,
				"] {", reason, " blocked by ", blocktype[t],
				" policy, whitelisted by ", blocktype[u],
				" policy}", NULL};
	log_writen(LOG_INFO, logmess);
}
