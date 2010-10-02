/** \file dns_helpers.c
 \brief DNS helper functions that do no network actions
 */
#include "qdns.h"

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
	const char *dt, *lastdt;

	if (!*h || (*h == '.'))
		return 1;
	while (*h) {
		if (!((*h >= 'a') && (*h <= 'z')) && !((*h >= 'A') && (*h <= 'Z'))  &&
			 (*h != '.') && (*h != '-') && !((*h >= '0') && (*h <= '9'))) {
			 return 1;
		}
		if (*h == '.') {
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
	dt = strrchr(host, '.');
	if (dt == NULL)
		return 1;
	/* the shortest top level domain has 2 characters, the host name
	 * must have at least one and there is one delimiter. */
	if ((h - dt) < 3)
		return 1;
	/* there is no top level domain ending with something different from a letter */
	h--;
	if (!(((*h >= 'a') && (*h <= 'z')) || ((*h >= 'A') && (*h <= 'Z'))))
		return 1;

	lastdt = host;
	/* each string between two dots must not exceed 63 characters */
	do {
		dt = strchr(lastdt + 1, '.');
		if ((dt != NULL) && (dt - lastdt > 64))
			return 1;
		lastdt = dt;
	} while (dt != NULL);

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
		free(thisip);
	}
}

/**
 * sort MX list by priority
 *
 * @param p list of MX entries
 */
void
sortmx(struct ips **p)
{
	struct ips *next, *res = NULL;

	/* make us live easy: copy first entry */
	res = *p;
	next = (*p)->next;
	(*p)->next = NULL;
	*p = next;

	while (next) {
		struct ips *this = res;
		struct ips *tmp = next->next;

		if (res->priority > next->priority) {
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
