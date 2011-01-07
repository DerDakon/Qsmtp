/** \file libowfatconn.c
 \brief connector functions for libowfat DNS functions
 */
#include <stdlib.h>
#include <stralloc.h>
#include <dns.h>
#include "libowfatconn.h"

/**
 * @param out result string will be stored here, memory is malloced
 * @param len length of res
 * @param host host name to look up
 * @return -1 on error, 0 on success
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
	*out = sa.s;
	*len = sa.len;
	return r;
}

/**
 * @param out result string will be stored here, memory is malloced
 * @param len length of res
 * @param host host name to look up
 * @return -1 on error, 0 on success
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
	*out = sa.s;
	*len = sa.len;
	return r;
}

/**
 * @param out result string will be stored here, memory is malloced
 * @param len length of res
 * @param host host name to look up
 * @return -1 on error, 0 on success
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
	*out = sa.s;
	*len = sa.len;
	return r;
}

/**
 * @param out TXT record of host will be stored here, memory is malloced
 * @param host name of host to look up
 * @return -1 on error, 0 on success
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
	if (r) {
		free(fqdn.s);
		return r;
	}
	r = stralloc_0(&sa);
	free(fqdn.s);
	if (!r) {
		free(sa.s);
		return -1;
	}
	*out = sa.s;
	return 0;
}

/**
 * @param out DNS name of host will be stored here, memory is malloced
 * @param ip IPv6 address of host to look up
 * @return -1 on error, 0 on success
 */
int
dnsname(char **out, const char *ip)
{
	stralloc sa = {.a = 0, .len = 0, .s = NULL};
	int r;

	r = dns_name6(&sa, ip);
	if (r)
		return r;
	if (!(r = stralloc_0(&sa))) {
		free(sa.s);
		return -1;
	}
	*out = sa.s;
	return 0;
}
