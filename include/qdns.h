/** \file qdns.h
 \brief headers of functions for DNS lookups and address validating
 */
#ifndef QSMTP_DNS_H
#define QSMTP_DNS_H

#include <netinet/in.h>
#include "sstring.h"

/** \struct ips
 \brief list of IP addresses for a given host
 
 This struct represents a member of an IP address list. It is used as return value
 by the ask_dns* functions. A complete list can be freed by calling freeips(). If
 this list represents a list of MX entries the priority field contains the priority
 given in DNS. If there is no MX entry at all and the A record is used instead the
 priority is set to 65536. If the list is not created by ask_dnsmx() then the value
 of the priority field is undefined.
 */
struct ips {
	struct in6_addr addr;	/**< IPv6 address */
	unsigned int priority;	/**< MX priority, undefined for A or AAAA */
	struct ips *next;	/**< pointer to next list entry */
};

/* lib/dns.c */

extern int ask_dnsmx(const char *, struct ips **) __attribute__ ((nonnull (1,2)));
extern int ask_dnsaaaa(const char *, struct ips **) __attribute__ ((nonnull (1,2)));
extern int ask_dnsa(const char *, struct ips **) __attribute__ ((nonnull (1)));
extern int ask_dnsname(const struct in6_addr *, char **) __attribute__ ((nonnull (1,2)));
extern void freeips(struct ips *) __attribute__ ((nonnull (1)));
extern int domainvalid(const char *) __attribute__ ((pure)) __attribute__ ((nonnull (1)));
extern void sortmx(struct ips **p) __attribute__ ((nonnull (1)));

/* qsmtpd/addrsyntax.c */

extern int checkaddr(const char *const) __attribute__ ((pure)) __attribute__ ((nonnull (1)));
extern int addrsyntax(char *in, const int flags, string *addr, char **more) __attribute__ ((pure)) __attribute__ ((nonnull (1)));

/* return codes of helovalid:
	-1: error
	 0: valid
	 1: helo is my name
	 2: helo is my IP address
	 3: helo is syntactically invalid
	 4: currently undefined
	 5: 2+3 (helo is my IP address, but not enclosed in '[]')
	 6, 7: currently undefined
*/
extern int helovalid(const char *) __attribute__ ((nonnull (1)));

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#endif
