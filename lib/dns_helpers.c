/** \file dns_helpers.c
 \brief DNS helper functions that do no network actions
 */
#include "dns.h"

/**
 * check if a string is a valid fqdn
 *
 * @param host the name to check
 * @return 0 if everything is ok 
 *         1 on syntax error
 *
 * if there is a standard function doing the same throw this one away
 */
int
domainvalid(const char *host)
{
	int dot = 0;	/* if there is a '.' in the address */
	const char *h = host;

	if (!*host || (*host == '.'))
		return 1;
	while (*host) {
		if (!((*host >= 'a') && (*host <= 'z')) && !((*host >= 'A') && (*host <= 'Z'))  &&
			 (*host != '.') && (*host != '-') && !((*host >= '0') && (*host <= '9'))) {
			 return 1;
		}
		if (*host == '.') {
			host++;
			dot = 1;
			if (*host == '.')
				return 1;
			continue;
		}
		host++;
	}
	if (((host - h) > 255) || ((host - h) < 5))
		return 1;
	/* there is no top level domain ending with something different from a letter */
	host--;
	if (!(((*host >= 'a') && (*host <= 'z')) || ((*host >= 'A') && (*host <= 'Z'))))
		return 1;
	return 1 - dot;
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
