#ifndef DNS_H
#define DNS_H

#include <netinet/in.h>
#include "sstring.h"

struct ips {
	struct in6_addr addr;
	int	priority;	/* MX priority, undefined for A or AAAA */
	struct ips *next;
};

extern int ask_dnsmx(const char *, struct ips **);
extern int ask_dnsa(const char *, struct ips **);
extern int domainvalid(const char *, const int);
extern int checkaddr(const char *, const int);
extern int addrsyntax(char *in, const int flags, string *addr, char **more);
extern void freeips(struct ips *);

/* these functions are from libowfat somehow, you must apply the supplied patch to libowfat to get them */

extern int dnsip4(char **, unsigned int *, const char *);
extern int dnsip6(char **, unsigned int *, const char *);
extern int dnstxt(char **, const char *);
extern int dnsmx(char **, unsigned int *, const char *);

#endif
