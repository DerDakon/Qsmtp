/** \file match.c
 \brief IP and domain matching functions
 */

#include <match.h>

#include <netinet/in.h>
#include <string.h>
#include <strings.h>

/**
 * check if an IPv4 address is in a given network
 *
 * @param ip the IP address to check (network byte order)
 * @param net the network to check (network byte order)
 * @param mask the network mask, must be 0 <= netmask <= 32
 * @return if address is within net/mask
 * @retval 1 on match
 * @retval 0 no match
 */
int
ip4_matchnet(const struct in6_addr *ip, const struct in_addr *net, const unsigned char mask)
{
	struct in_addr m;

	/* do this explicitely here so we don't rely on how the compiler handles
	 * the shift overflow below. */
	if (mask == 0)
		return 1;

	/* constuct a bit mask out of the net length.
	 * remoteip and ip are network byte order, it's easier
	 * to convert mask to network byte order than both
	 * to host order. It's ugly, isn't it? */
	m.s_addr = htonl(-1 - ((1U << (32 - mask)) - 1));

	return ((ip->s6_addr32[3] & m.s_addr) == (net->s_addr & m.s_addr));
}

/**
 * check if an IPv6 address is in a given network
 *
 * @param ip the IP address to check (network byte order)
 * @param net the network to check (network byte order)
 * @param mask the network mask, must be 0 <= netmask <= 128
 * @return if address is within net/mask
 * @retval 1 address is within the net/mask
 * @retval 0 address is not within net/mask
 */
int
ip6_matchnet(const struct in6_addr *ip, const struct in6_addr *net, const unsigned char mask)
{
	struct in6_addr maskv6;

	memset(maskv6.s6_addr, 0, sizeof(maskv6.s6_addr));
	for (int i = 0; i < mask / 32; ++i) {
		maskv6.s6_addr32[i] = -1;
	}
	if ((mask % 32) != 0)
		maskv6.s6_addr32[mask / 32] = htonl(-1 - ((1U << (32 - (mask % 32))) - 1));

	for (int i = 3; i >= 0; i--) {
		if ((ip->s6_addr32[i] & maskv6.s6_addr32[i]) != (net->s6_addr32[i] & maskv6.s6_addr32[i])) {
			return 0;
		}
	}
	return 1;
}

/**
 * check if a given expression matches a domain
 *
 * @param domain the domain to check
 * @param dl length of domain
 * @param expr the expression to match
 * @retval 1 on match
 * @retval 0 otherwise
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
