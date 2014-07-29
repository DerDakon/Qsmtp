/** \file qdns.h
 \brief headers of functions for DNS lookups
 */
#ifndef QSMTP_DNS_H
#define QSMTP_DNS_H

#include <netinet/in.h>

/** @enum mx_special_priorities
 * @brief values used as priority in struct ips to reflect special conditions
 */
enum mx_special_priorities {
	MX_PRIORITY_IMPLICIT = 65536,	/**< used for implicit MX entries (i.e. A or AAAA) */
	MX_PRIORITY_USED = 65537,	/**< the entry has already been tried */
	MX_PRIORITY_CURRENT = 65538	/**< used to mark the entry currently in use */
};

/** @struct ips
 @brief list of IP addresses for a given host

 This struct represents a member of an IP address list. It is used as return value
 by the ask_dns* functions. A complete list can be freed by calling freeips(). If
 this list represents a list of MX entries the priority field contains the priority
 given in DNS. If there is no MX entry at all and the A record is used instead the
 priority is set to MX_PRIORITY_IMPLICIT. If the list is not created by ask_dnsmx()
 then the value of the priority field is undefined.
 */
struct ips {
	struct in6_addr addr;	/**< IPv6 address */
	char *name;		/**< name of the MX */
	unsigned int priority;	/**< MX priority, undefined for A or AAAA */
	struct ips *next;	/**< pointer to next list entry */
};

/* lib/qdns.c */

extern int ask_dnsmx(const char *, struct ips **) __attribute__ ((nonnull (1,2)));
extern int ask_dnsaaaa(const char *, struct in6_addr **) __attribute__ ((nonnull (1,2)));
extern int ask_dnsa(const char *, struct in6_addr **) __attribute__ ((nonnull (1)));
extern int ask_dnsname(const struct in6_addr *, char **) __attribute__ ((nonnull (1,2)));

/* lib/dnshelpers.c */

extern void freeips(struct ips *);
extern int domainvalid(const char * const) __attribute__ ((pure)) __attribute__ ((nonnull (1)));
extern void sortmx(struct ips **p) __attribute__ ((nonnull (1)));
extern struct ips *in6_to_ips(struct in6_addr *a, unsigned int cnt, const unsigned int priority) __attribute__ ((nonnull (1)));

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

/** @enum dns_errors
 * @brief error codes returned by the DNS lookup functions
 */
enum dns_errors {
	DNS_ERROR_LOCAL = -1,	/**< a local error during DNS lookup, errno is set */
	DNS_ERROR_TEMP = -2,	/**< a temporary DNS error */
	DNS_ERROR_PERM = -3	/**< a permanent DNS error */
};

#endif
