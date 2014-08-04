/** \file ipme.c
 * \brief functions to filter out IP addresses of the local machine
 */

#include <ipme.h>

#include <qdns.h>

#include <assert.h>
#include <ifaddrs.h> 
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h> 
#include <sys/types.h> 

/**
 * remove all IP addresses of the local machine from IP list
 *
 * @param ipl list of IP addresses
 * @returns cleaned list
 * @retval NULL all listed addresses are local ones
 *
 * The address structs that match the local machine are freed.
 *
 * If any errors are encountered while this function runs (e.g.
 * a function called runs out of memory) the original list will
 * be returned.
 */
struct ips *
filter_my_ips(struct ips *ipl)
{
	struct ifaddrs *ifap, *curi;
	struct ips *ret = ipl;

	if (getifaddrs(&ifap) != 0)
		return ipl;

	for (curi = ifap; curi != NULL; curi = curi->ifa_next) {
		struct ips *tmp;
		struct ips *prev = NULL;

		if (curi->ifa_addr == NULL)
			continue;

		switch (curi->ifa_addr->sa_family) {
		case AF_INET:
			break;
#ifndef IPV4ONLY
		case AF_INET6:
			break;
#endif /* IPV4ONLY */
		default:
			continue;
		}

		tmp = ret;
		while (tmp != NULL) {
			assert(tmp->addr == &tmp->ad);
			assert(tmp->count == 1);

			if (curi->ifa_addr->sa_family == AF_INET) {
				/* either configured as localhost or 127.0.0./8 or 0.0.0.0 */
				if (!IN6_IS_ADDR_V4MAPPED(tmp->addr) ||
						((tmp->addr->s6_addr32[3] != ((struct sockaddr_in *)curi->ifa_addr)->sin_addr.s_addr) &&
						(tmp->addr->s6_addr[12] != IN_LOOPBACKNET) && (tmp->addr->s6_addr32[3] != 0))) {
					prev = tmp;
					tmp = tmp->next;
					continue;
				}
#ifndef IPV4ONLY
			} else if (!IN6_ARE_ADDR_EQUAL(tmp->addr, &((struct sockaddr_in6 *)curi->ifa_addr)->sin6_addr)) {
				prev = tmp;
				tmp = tmp->next;
				continue;
#endif /* IPV4ONLY */
			}

			if (prev) {
				prev->next = tmp->next;
				tmp->next = NULL;
				freeips(tmp);
				tmp = prev->next;
			} else {
				/* the first result was deleted */
				if (ret == tmp)
					ret = ret->next;

				prev = tmp;
				tmp = tmp->next;
				prev->next = NULL;
				freeips(prev);
				prev = NULL;
			}
		}
	}

	freeifaddrs(ifap);

	return ret;
}
