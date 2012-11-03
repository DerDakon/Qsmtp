/** \file libowfatconn.c
 \brief connector functions for libowfat DNS functions
 */
#include <stdlib.h>
#include <stralloc.h>
#include <dns.h>
#include <netinet/in.h>
#include "libowfatconn.h"

/**
 * @brief query DNS for IPv6 address of host
 *
 * @param out result string will be stored here, memory is malloced
 * @param len length of res
 * @param host host name to look up
 * @retval 0 success
 * @retval -1 an error occurred, errno is set
 */
int
dnsip6(char **out, unsigned int *len, const char *host)
{
	stralloc fqdn = {.a = 0, .len = 0, .s = NULL};
	stralloc sa = {.a = 0, .len = 0, .s = NULL};
	int r;

	if (!stralloc_copys(&fqdn, host))
		return -1;

	r = dns_ip6(&sa, &fqdn);
	free(fqdn.s);
	if (r == 0) {
		*out = sa.s;
		*len = sa.len;
	} else {
		free(sa.s);
	}
	return r;
}

/**
 * @brief query DNS for IPv4 address of host
 *
 * @param out result string will be stored here, memory is malloced
 * @param len length of res
 * @param host host name to look up
 * @retval 0 success
 * @retval -1 an error occurred, errno is set
 */
int
dnsip4(char **out, unsigned int *len, const char *host)
{
	stralloc fqdn = {.a = 0, .len = 0, .s = NULL};
	stralloc sa = {.a = 0, .len = 0, .s = NULL};
	int r;

	if (!stralloc_copys(&fqdn, host))
		return -1;

	r = dns_ip4(&sa, &fqdn);
	free(fqdn.s);
	if (r == 0) {
		*out = sa.s;
		*len = sa.len;
	} else {
		free(sa.s);
	}
	return r;
}

/**
 * @brief query DNS for MX entries
 *
 * @param out result string will be stored here, memory is malloced
 * @param len length of res
 * @param host host name to look up
 * @retval 0 success
 * @retval -1 an error occurred, errno is set
 */
int
dnsmx(char **out, unsigned int *len, const char *host)
{
	stralloc fqdn = {.a = 0, .len = 0, .s = NULL};
	stralloc sa = {.a = 0, .len = 0, .s = NULL};
	int r;

	if (!stralloc_copys(&fqdn, host))
		return -1;

	r = dns_mx(&sa, &fqdn);
	free(fqdn.s);
	if (r == 0) {
		*out = sa.s;
		*len = sa.len;
	} else {
		free(sa.s);
	}
	return r;
}

/**
 * @brief query DNS for TXT entries
 *
 * @param out TXT record of host will be stored here, memory is malloced
 * @param host name of host to look up
 * @retval 0 success
 * @retval -1 an error occurred, errno is set
 */
int
dnstxt(char **out, const char *host)
{
	stralloc sa = {.a = 0, .len = 0, .s = NULL};
	stralloc fqdn = {.a = 0, .len = 0, .s = NULL};
	int r;

	if (!stralloc_copys(&fqdn, host))
		return -1;

	r = dns_txt(&sa, &fqdn);
	free(fqdn.s);
	if (r) {
		free(sa.s);
		return r;
	}

	r = stralloc_0(&sa);

	if (!r) {
		free(sa.s);
		return -1;
	}
	*out = sa.s;
	return 0;
}

/**
 * @brief query DNS for name for a given IP address
 *
 * @param out DNS name of host will be stored here, memory is malloced
 * @param ip IPv6 address of host to look up
 * @retval 0 success
 * @retval -1 an error occurred, errno is set
 */
int
dnsname(char **out, const struct in6_addr *ip)
{
	stralloc sa = {.a = 0, .len = 0, .s = NULL};
	int r;

	r = dns_name6(&sa, (const char *)ip->s6_addr);
	if (r) {
		free(sa.s);
		return r;
	}
	if (!(r = stralloc_0(&sa))) {
		free(sa.s);
		return -1;
	}
	*out = sa.s;
	return 0;
}
