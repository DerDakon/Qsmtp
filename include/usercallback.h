#ifndef USERCALLBACK_H
#define USERCALLBACK_H
#include "sstring.h"
#include "qsmtpd.h"

struct userconf {
	string domainpath;		/* Path of the domain for domain settings */
	string userpath;		/* Path of the user directory where the user stores it's own settings */
	char **userconf;		/* contents of the "filterconf" file in user directory (or NULL) */
	char **domainconf;		/* dito for domain directory */
};

extern char **globalconf;		/* contents of the global "filterconf" file (or NULL) */

/* function to open a policy file either in user or domain directory */
extern int getfile(const struct userconf *, const char *, int *);
/* function to open a policy file either in user or domain directory or fall back to global */
extern int getfileglobal(const struct userconf *, const char *, int *);
/* look up value in user/domain "filterconf" file */
extern long getsetting(const struct userconf *, const char *, int *);
/* like getsetting, but fall back to global file if no match */
extern long getsettingglobal(const struct userconf *, const char *, int *);

/* this is a function for a user policy callback
 *
 * ds:     the struct with the paths of domain- and userpath
 * logmsg: store here a reference to the message to write into logfile or NULL if you logged yourself
 * type:   which policy matched (user, domain, global)
 *
 * the return codes are:
 * -1: error condition, errno is set
 * 0: policy passed
 * 1: policy denied, ucb_func wrote error code
 * 2: policy denied, calling function should announce general policy error
 * 3: policy denied, calling function should say recipient does not exist
 * 4: policy denied, calling function should announce temporary error
 * 5: policy passed, mail is whitelisted (do not call other functions)
 */

typedef int (*rcpt_cb)(const struct userconf *, char **logmsg, int *t);

extern rcpt_cb rcpt_cbs[];

extern const char *blocktype[];

extern void logwhitelisted(const char *reason, const int t, const int u);

#define THISRCPT (thisrecip->to.s)

#endif
