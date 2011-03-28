/** \file userfilters.h
 \brief common function definitions for all user filters
 */
#ifndef USERFILTERS_H
#define USERFILTERS_H
#include <sys/types.h>
#include <sys/queue.h>
#include "sstring.h"
#include "qsmtpd.h"

struct userconf {
	string domainpath;		/**< Path of the domain for domain settings */
	string userpath;		/**< Path of the user directory where the user stores it's own settings */
	char **userconf;		/**< contents of the "filterconf" file in user directory (or NULL) */
	char **domainconf;		/**< dito for domain directory */
};

extern const char **globalconf;

extern int getfile(const struct userconf *, const char *, int *);
extern int getfileglobal(const struct userconf *, const char *, int *);
extern long getsetting(const struct userconf *, const char *, int *);
extern long getsettingglobal(const struct userconf *, const char *, int *);

/** \var rcpt_cb
 * \brief this is a function for a user filter
 *
 * \param ds:     the struct with the paths of domain- and userpath
 * \param logmsg: store here a reference to the message to write into logfile or NULL if you logged yourself
 * \param type:   which policy matched (user, domain, global)
 *
 * \return \arg \c -1: error condition, errno is set
 *         \arg \c 0: policy passed
 *         \arg \c 1: policy denied, ucb_func wrote error code
 *         \arg \c 2: policy denied, calling function should announce general policy error
 *         \arg \c 3: policy denied, calling function should say recipient does not exist
 *         \arg \c 4: policy denied, calling function should announce temporary error
 *         \arg \c 5: policy passed, mail is whitelisted (do not call other functions)
 */
typedef int (*rcpt_cb)(const struct userconf *ds, const char **logmsg, int *t);

extern rcpt_cb rcpt_cbs[];
extern rcpt_cb late_rcpt_cbs[];

extern const char *blocktype[];

extern void logwhitelisted(const char *, const int, const int);

#define THISRCPT (thisrecip->to.s)

TAILQ_HEAD(pftailhead, pfixpol) pfixhead;

/*! \struct pfixpol
 Describes the settings for one Postfix policy daemon
 */
struct pfixpol {
	TAILQ_ENTRY(pfixpol) entries;	/**< List pointers of policy daemons. */
	char	*name;			/**< name for this filter (to be used in log and userconf) */
	pid_t	pid;			/**< pid of daemon or 0 if not running */
	int	fd;			/**< pipe for communication */
};

#define PFIXPOLDIR	"/var/qmail/control/postfixpol"
#define PFIXSPOOLDIR	"/var/spool/Qsmtp"

#endif
