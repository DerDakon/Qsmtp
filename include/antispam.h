#ifndef ANTISPAM_H
#define ANTISPAM_H

#include <netinet/in.h>
#include "sstring.h"

extern int check_rbl(const struct in6_addr *, const char **, char **);
extern inline void tarpit(void);
extern int check_ip4(const struct in6_addr *, const unsigned char *, const unsigned int);
extern int check_ip6(const struct in6_addr *, const unsigned char *, const unsigned int);
extern int spflookup(const char *, string *);
extern int domainmatch(const char *, const unsigned int, const char **);

#define SPF_HARD_ERROR -2
#define SPF_TEMP_ERROR -1
#define SPF_NONE 0
#define SPF_PASS 1
#define SPF_NEUTRAL 2
#define SPF_SOFTFAIL 3
#define SPF_FAIL 4

#endif
