#ifndef ANTISPAM_H
#define ANTISPAM_H

#include <netinet/in.h>
#include "sstring.h"

/* qsmtpd/antispam.c */

extern int check_rbl(char *const *, char **);
extern inline void tarpit(void);
extern int domainmatch(const char *, const unsigned int, const char **);
extern int ip4_matchnet(const struct in_addr *, const struct in_addr *, const int);
extern int lookupipbl(int);

/* qsmtpd/spf.c */

extern int spflookup(const char *, const int);
extern int spfreceived(int, const int);

#define SPF_NONE	0
#define SPF_PASS	1
#define SPF_NEUTRAL	2
#define SPF_SOFTFAIL	3
#define SPF_FAIL	4
#define SPF_UNKNOWN	5
#define SPF_LOOP	6
#define SPF_TEMP_ERROR 14
#define SPF_HARD_ERROR 15

#endif
