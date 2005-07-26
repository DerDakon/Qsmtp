/** \file match.c
 \brief IP and domain matching functions
 */
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include "match.h"

/**
 * check if an IPv4 address is in a given network
 *
 * @param ip the IP address to check (network byte order)
 * @param net the network to check (network byte order)
 * @param mask the network mask, must be 8 <= netmask <= 32
 * @return 1 on match, 0 else
 */
int
ip4_matchnet(const struct in6_addr *ip, const struct in_addr *net, const unsigned char mask)
{
	struct in_addr m;
	/* constuct a bit mask out of the net length.
	 * remoteip and ip are network byte order, it's easier
	 * to convert mask to network byte order than both
	 * to host order. It's ugly, isn't it? */
	m.s_addr = htonl(-1 - ((1 << (32 - mask)) - 1));

	return ((ip->s6_addr32[3] & m.s_addr) == net->s_addr);
}

/**
 * check if an IPv6 address is in a given network
 *
 * @param ip the IP address to check (network byte order)
 * @param net the network to check (network byte order)
 * @param mask the network mask, must be 8 <= netmask <= 128
 * @return 1 on match, 0 else
 */
int
ip6_matchnet(const struct in6_addr *ip, const struct in6_addr *net, const unsigned char mask)
{
	struct in6_addr maskv6;
	int flag = 4, i;

	/* construct a bit mask out of the net length */
	if (mask < 32) {
		maskv6.s6_addr32[0] = 0xffffffff;
		maskv6.s6_addr32[1] = 0xffffffff;
		maskv6.s6_addr32[2] = 0xffffffff;
		/* remoteip and ip are network byte order, it's easier
			* to convert mask to network byte order than both
			* to host order. We do it at this point because we only
			* need to change one word per mask, the other 3 will stay
			* the same before and after htonl() */
		maskv6.s6_addr32[3] = htonl(-1 - (1 << ((32 - mask) - 1)));
	} else {
		maskv6.s6_addr32[3] = 0;
		if (mask < 64) {
			maskv6.s6_addr32[0] = 0xffffffff;
			maskv6.s6_addr32[1] = 0xffffffff;
			maskv6.s6_addr32[2] = htonl(-1 - (1 << ((64 - mask) - 1)));
		} else {
			maskv6.s6_addr32[2] = 0;
			if (mask < 96) {
				maskv6.s6_addr32[0] = 0xffffffff;
				maskv6.s6_addr32[1] = htonl(-1 - (1 << ((96 - mask) - 1)));
			} else {
				maskv6.s6_addr32[0] = htonl(-1 - (1 << ((128 - mask) - 1)));
				maskv6.s6_addr32[1] = 0;
			}
		}
	}

	for (i = 3; i >= 0; i--) {
		if ((ip->s6_addr32[i] & maskv6.s6_addr32[i]) == net->s6_addr32[i]) {
			flag--;
		}
	}
	return !flag;
}

/**
 * check if a given expression matches a domain
 *
 * @param domain the domain to check
 * @param dl length of domain
 * @param expr the expression to match
 * @return 1 on match, 0 otherwise
 */
int
matchdomain(const char *domain, const size_t dl, const char *expr)
{
	size_t el = strlen(expr);

	if (el > dl)
		return 0;

	if (*expr == '.') {
		return !strcasecmp(domain + (dl - el), expr);
	} else if (el == dl) {
		return !strcasecmp(domain, expr);
	}
	return 0;
}
