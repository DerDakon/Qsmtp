/** \file dns_helpers.c
 \brief DNS helper functions that do no network actions
 */

#include <qdns.h>

#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/**
 * check if a string is a valid fqdn
 *
 * @param host the name to check
 * @return if the string is a valid domain name
 * @retval 0 everything is ok
 * @retval 1 on syntax error
 *
 * if there is a standard function doing the same throw this one away
 */
int
domainvalid(const char * const host)
{
	const char *h = host;
	const char *dt = NULL;

	if (!*h || (*h == '.'))
		return 1;
	while (*h) {
		if (!((*h >= 'a') && (*h <= 'z')) && !((*h >= 'A') && (*h <= 'Z'))  &&
			 (*h != '.') && (*h != '-') && !((*h >= '0') && (*h <= '9'))) {
			 return 1;
		}
		if (*h == '.') {
			const char *lastdt = (dt == NULL) ? host : dt;

			/* each string between two dots must not exceed 63 characters */
			if (h - lastdt > 64)
				return 1;
			dt = h;
			h++;
			/* empty parts are not allowed */
			if (*h == '.')
				return 1;
			continue;
		}
		h++;
	}
	/* maximum length is 255 characters */
	if ((h - host) > 255)
		return 1;
	/* a FQDN must have at least one dot */
	if (dt == NULL)
		return 1;
	/* the shortest top level domain has 2 characters, the host name
	 * must have at least one and there is one delimiter. The 63 character 
	 * limit also applies here. */
	if (((h - dt) < 3) || ((h - dt) > 64))
		return 1;
	/* there is no top level domain ending with something different from a letter */
	h--;
	if (!(((*h >= 'a') && (*h <= 'z')) || ((*h >= 'A') && (*h <= 'Z'))))
		return 1;

	return 0;
}

/**
 * free memory of IP list
 *
 * @param p IP list to free
 */
void
freeips(struct ips *p)
{
	while (p) {
		struct ips *thisip = p;

		p = thisip->next;
		free(thisip->name);
		free(thisip->addr);
		free(thisip);
	}
}

static int
ip6_sort(const void *l, const void *r)
{
	/* If IPv6 addresses are permitted they are considered smaller,
	 * so they will be first in the list and be tried first. In case
	 * they are not allowed they are considered greater so they end
	 * up at the end of the list and can easily be omitted. */
#ifdef IPV4ONLY
	const int ret = -1;
#else
	const int ret = 1;
#endif
	const struct in6_addr *lip = l;
	const struct in6_addr *rip = r;
	const int l_is_4 = IN6_IS_ADDR_V4MAPPED(lip);
	const int r_is_4 = IN6_IS_ADDR_V4MAPPED(rip);

	if (l_is_4 == r_is_4)
		return 0;
	else if (l_is_4)
		return ret;
	else
		return -ret;
}

/**
 * @brief sort MX list by priority
 * @param p list of MX entries
 *
 * Inside each entry of p the IPv6 entries are moved to the front so that
 * IPv6 addresses are prefered. If 2 entries of p have the same priority
 * those that contain IPv6 addresses will be moved to the front for the
 * same reason.
 *
 * If IPV4ONLY is defined all IPv6 addresses will be stripped from the list.
 */
void
sortmx(struct ips **p)
{
	struct ips *next;

	/* first sort the IPs in every entry */
	for (next = *p; next != NULL; next = next->next) {
		if (next->count == 1)
			continue;

		qsort(next->addr, next->count, sizeof(*next->addr),
				ip6_sort);
	}

#ifdef IPV4ONLY
	/* "remove" all IPv6 entries */
	for (next = *p; next != NULL; next = next->next) {
		unsigned short s;

		/* if the first entry is an IPv6 address the whole MX consists of
		 * such as they were sorted last before */
		if (!IN6_IS_ADDR_V4MAPPED(next->addr)) {
			next->priority = MX_PRIORITY_USED;
			continue;
		}

		/* Check if the list included IPv6 entries. Since they come as a
		 * block at the end just reduce the count entry to not include
		 * them anymore. */
		for (s = 1; s < next->count; s++) {
			if (!IN6_IS_ADDR_V4MAPPED(next->addr + s)) {
				next->count = s - 1;
				break;
			}
		}
	}
#endif

	/* make us live easy: copy first entry */
	struct ips *res = *p;
	next = (*p)->next;
	(*p)->next = NULL;
	*p = next;

	while (next) {
		struct ips *this = res;
		struct ips *tmp = next->next;

		if ((res->priority > next->priority)
#ifndef IPV4ONLY
				|| ((res->priority == next->priority)
					&& IN6_IS_ADDR_V4MAPPED(res->addr)
					&& !IN6_IS_ADDR_V4MAPPED(next->addr))
#endif
				) {
			next->next = res;
			res = next;
		} else {
			while (this->next && (this->next->priority <= next->priority)) {
				this = this->next;
			}
			tmp = next->next;
			next->next = this->next;
			this->next = next;
		}
		next = tmp;
	}

	*p = res;
}

/**
 * @brief convert an array of in6_addr structs to a list of struct ips
 * @param a the input array
 * @param cnt the address count in a (must be >0)
 * @param priority priority of the new records
 * @return list of struct ips
 * @retval NULL an allocation error happened during conversion
 *
 * a will always be freed.
 */
struct ips *
in6_to_ips(struct in6_addr *a, unsigned int cnt, const unsigned int priority)
{
	assert(cnt > 0);

	struct ips *res = malloc(sizeof(*res));
	if (res == NULL) {
		free(a);
		return NULL;
	}

	res->addr = a;
	res->count = cnt;
	res->priority = priority;
	res->name = NULL;
	res->next = NULL;

	return res;
}

/**
 * @brief read an IPv4 address and convert it to a v4mapped IPv6 address
 * @param str the string to read in
 * @param addr where to store the resulting address
 * @return the same values as inet_pton()
 * @retval 1 address was successfully read in
 */
int
inet_pton_v4mapped(const char *str, struct in6_addr *addr)
{
	struct in_addr tmp;
	const int r = inet_pton(AF_INET, str, &tmp);

	if (r <= 0)
		return r;

	*addr = in_addr_to_v4mapped(&tmp);

	return r;
}
