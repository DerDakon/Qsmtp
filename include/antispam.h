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

#define SPF_NONE	0
#define SPF_PASS	1
#define SPF_NEUTRAL	2
#define SPF_SOFTFAIL	3
#define SPF_FAIL_PERM	4
#define SPF_FAIL_MALF	5
#define SPF_FAIL_NONEX	6
#define SPF_UNKNOWN	7
#define SPF_TEMP_ERROR	8
#define SPF_HARD_ERROR	9
#define SPF_IGNORE	15

#define SPF_FAIL(x) (((x) == SPF_FAIL_PERM) || ((x) == SPF_FAIL_MALF) || ((x) == SPF_FAIL_NONEX))

#endif
