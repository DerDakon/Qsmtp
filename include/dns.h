#ifndef DNS_H
#define DNS_H

#include <netinet/in.h>
#include "sstring.h"

struct ips {
	struct in6_addr addr;
	unsigned int priority;	/* MX priority, undefined for A or AAAA */
	struct ips *next;
};

/* lib/dns.c */

extern int ask_dnsmx(const char *, struct ips **);
extern int ask_dnsaaaa(const char *, struct ips **);
extern int ask_dnsa(const char *, struct ips **);
extern void freeips(struct ips *);
extern int __attribute__ ((pure)) domainvalid(const char *);

/* qsmtpd/addrsyntax.c */

extern int __attribute__ ((pure)) checkaddr(const char *);
extern int __attribute__ ((pure)) addrsyntax(char *in, const int flags, string *addr, char **more);

/* return codes of helovalid:
	-1: error
	 0: valid
	 1: helo is my name
	 2: helo is my IP address
	 3: helo is syntactically invalid
	 4: currently undefined
	 5: 2+3 (helo is my IP address, but not enclosed in '[]' which is broken
	 6, 7: currently undefined
*/
extern int helovalid(const char *);

/* these functions are from libowfat somehow, you must apply the supplied patch to libowfat to get them */

extern int dnsip4(char **, unsigned int *, const char *);
extern int dnsip6(char **, unsigned int *, const char *);
extern int dnstxt(char **, const char *);
extern int dnsmx(char **, unsigned int *, const char *);

#endif
