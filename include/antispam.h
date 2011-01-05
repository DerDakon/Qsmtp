/** \file antispam.h
 \brief headers of antispam helper functions
 */
#ifndef ANTISPAM_H
#define ANTISPAM_H

/* qsmtpd/antispam.c */

extern void dotip6(char *);
extern int check_rbl(char *const *, char **);
extern void tarpit(void);
extern int domainmatch(const char *, const unsigned int, const char **);
extern int lookupipbl(int);
extern int reverseip4(char *);

/* qsmtpd/spf.c */

extern int check_host(const char *);
extern int spfreceived(int, const int);

#define SPF_NONE	0	/**< no SPF policy given */
#define SPF_PASS	1	/**< host matches SPF policy */
#define SPF_NEUTRAL	2	/**< host has neutral match in SPF policy */
#define SPF_SOFTFAIL	3	/**< host has softfail match in SPF policy */
#define SPF_FAIL_PERM	4	/**< host is denied by SPF policy */
#define SPF_FAIL_MALF	5	/**< SPF entry is malformed */
#define SPF_FAIL_NONEX	6	/**< SPF entry has nonexistent include */
#define SPF_TEMP_ERROR	7	/**< temporary DNS error while SPF testing */
#define SPF_HARD_ERROR	8	/**< permanent DNS error while SPF testing */
#define SPF_IGNORE	15	/**< SPF policy for this host will not be tested */

/** \def SPF_FAIL
 check if one of the conditions is given to fail SPF policy
 */
#define SPF_FAIL(x) (((x) == SPF_FAIL_PERM) || ((x) == SPF_FAIL_MALF) || ((x) == SPF_FAIL_NONEX))

#endif
