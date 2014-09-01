/** \file antispam.h
 \brief headers of antispam helper functions
 */
#ifndef ANTISPAM_H
#define ANTISPAM_H

#include <sys/types.h>

/* qsmtpd/antispam.c */

extern void dotip6(char *);
extern int check_rbl(char *const *, char **) __attribute__ ((nonnull (1)));
extern void tarpit(void);
extern int domainmatch(const char *fqdn, const size_t len, const char **list);
extern int lookupipbl(int);

/* qsmtpd/spf.c */

extern int check_host(const char *);
extern int spfreceived(int, const int);

enum spf_eval_result {
	SPF_NONE = 0,	/**< no SPF policy given */
	SPF_PASS = 1,	/**< host matches SPF policy */
	SPF_NEUTRAL = 2,	/**< host has neutral match in SPF policy */
	SPF_SOFTFAIL = 3,	/**< host has softfail match in SPF policy */
	SPF_FAIL = 4,	/**< host is denied by SPF policy */
	SPF_PERMERROR = 5,	/**< SPF entry is malformed */
	SPF_TEMPERROR = 7,	/**< temporary DNS error while SPF testing */
	SPF_DNS_HARD_ERROR = 8,	/**< permanent DNS error while SPF testing */
	SPF_IGNORE = 15	/**< SPF policy for this host will not be tested */
};

/** \def SPF_IS_FAILURE
 check if one of the conditions is given to fail SPF policy
 */
#define SPF_IS_FAILURE(x) (((x) == SPF_FAIL) || ((x) == SPF_PERMERROR))

#endif
