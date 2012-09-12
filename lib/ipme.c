#include "ipme.h"

#include "qdns.h"

#include <sys/types.h> 
#include <sys/socket.h> 
#include <ifaddrs.h> 
#include <string.h>

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
			if (curi->ifa_addr->sa_family == AF_INET) {
				if (!IN6_IS_ADDR_V4MAPPED(&tmp->addr) ||
						tmp->addr.s6_addr32[3] != ((struct sockaddr_in *)curi->ifa_addr)->sin_addr.s_addr) {
					prev = tmp;
					tmp = tmp->next;
					continue;
				}
#ifndef IPV4ONLY
			} else if (memcmp(tmp->addr.s6_addr32, ((struct sockaddr_in6 *)curi->ifa_addr)->sin6_addr.s6_addr32, sizeof(tmp->addr.s6_addr32)) != 0) {
				prev = tmp;
				tmp = tmp->next;
				continue;
#endif /* IPV4ONLY */
			}
			if (prev) {

				prev->next = tmp->next;
				free(tmp);
				tmp = prev->next;
			} else {
				/* the first result was deleted */
				if (ret == tmp)
					ret = ret->next;

				prev = tmp;
				tmp = tmp->next;
				free(prev);
				prev = NULL;
			}
		}
	}

	freeifaddrs(ifap);

	return ret;
}
