/** \file qdns.c
 \brief DNS query functions
 */

#include <qdns.h>

#include <libowfatconn.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * \brief get info out of the DNS
 *
 * \param name the name to look up
 * \param result first element of a list of results will be placed
 * \retval  0 on success
 * \retval  1 if host is not existent
 * \retval  2 if temporary DNS error
 * \retval  3 if permanent DNS error
 * \retval -1 on error
 */
int
ask_dnsmx(const char *name, struct ips **result)
{
	int i;
	char *r;
	size_t l;
	char *s;
	struct ips **q = result;
	int errtype = 0;

	i = dnsmx(&r, &l, name);

	if ((i != 0) && (errno != ENOENT)) {
		switch (errno) {
		case ETIMEDOUT:
		case EAGAIN:
			return DNS_ERROR_TEMP;
		case ENFILE:
		case EMFILE:
		case ENOBUFS:
			errno = ENOMEM;
			/* fallthrough */
		case ENOMEM:
			return DNS_ERROR_LOCAL;
		case ENOENT:
			return 1;
		default:
			return DNS_ERROR_PERM;
		}
	}

	s = r;

	/* there is no MX record, so we look for an AAAA record */
	if (!l) {
		int rc = ask_dnsaaaa(name, result);

		if (!rc) {
			struct ips *a = *result;

			while (a) {
				/* the DNS priority is 2 bytes long so 65536 can
					never be returned from a real DNS_MX lookup */
				a->priority = 65536;
				a = a->next;
			}
		}
		return rc;
	}

	while (r + l > s) {
		struct ips *p;
		int rc;

		rc = ask_dnsaaaa(s + 2, &p);
		if (rc == DNS_ERROR_LOCAL) {
			freeips(*result);
			free(r);
			if (errno == ENOMEM)
				return DNS_ERROR_LOCAL;
			return DNS_ERROR_TEMP;
		} else if (!rc) {
			struct ips *u;
			unsigned int pri = ntohs(*((unsigned short *) s));

			/* add the new results to the list */
			*q = p;
			/* set priority for each of the new entries */
			for (u = p; u; u = p->next) {
				u->priority = pri;
				p = u;
			}
			q = &(p->next);
		} else {
			errtype = (1 << -rc);
		}
		s += 3 + strlen(s + 2);
	}

	free(r);

	if (*result)
		return 0;
	else if (errtype & 4)
		return DNS_ERROR_TEMP;
	else if (errtype & 2)
		return 1;
	else
		return DNS_ERROR_PERM;
}

/**
 * \brief get AAAA record from of the DNS
 *
 * \param name the name to look up
 * \param result first element of a list of results will be placed
 * \retval  0 on success
 * \retval  1 if host is not existent
 * \retval  2 if temporary DNS error
 * \retval  3 if permanent DNS error
 * \retval -1 on error
 */
int
ask_dnsaaaa(const char *name, struct ips **result)
{
	int i;
	char *r;
	size_t l;
	char *s;
	struct ips **q = result;

	*result = NULL;

	i = dnsip6(&r, &l, name);
	if (i < 0) {
		free(r);
		switch (errno) {
		case ETIMEDOUT:
		case EAGAIN:
			return DNS_ERROR_TEMP;
		case ENFILE:
		case EMFILE:
		case ENOBUFS:
			errno = ENOMEM;
			/* fallthrough */
		case ENOMEM:
			return DNS_ERROR_LOCAL;
		case ENOENT:
			return 1;
		default:
			return DNS_ERROR_PERM;
		}
	}

	s = r;

	if (!l)
		return 1;

	while (r + l > s) {
		struct ips *p = malloc(sizeof(*p));

		if (!p) {
			freeips(*result);
			free(r);
			return DNS_ERROR_LOCAL;
		}
		*q = p;
		p->next = NULL;
		memcpy(&(p->addr), s, 16);

		q = &(p->next);
		s += 16;
	}

	free(r);
	return 0;
}

/**
 * @brief get A record from of the DNS
 * @param name the name to look up
 * @param result first element of a list of results will be placed, or NULL if only return code is of interest
 * @return if records have been found
 * @retval 0 on success
 * @retval 1 host does not exist
 * @retval -1 on error (errno is set)
 * @retval -2 temporary DNS error
 * @retval -3 permanent DNS error
 */
int
ask_dnsa(const char *name, struct ips **result)
{
	int i;
	char *r;
	size_t l;

	i = dnsip4(&r, &l, name);
	if (i < 0) {
		switch (errno) {
		case ETIMEDOUT:
		case EAGAIN:
			return DNS_ERROR_TEMP;
		case ENFILE:
		case EMFILE:
		case ENOBUFS:
			errno = ENOMEM;
			/* fallthrough */
		case ENOMEM:
			return DNS_ERROR_LOCAL;
		case ENOENT:
			return 1;
		default:
			return DNS_ERROR_PERM;
		}
	}

	if (result) {
		char *s = r;
		struct ips **q = result;

		if (!l) {
			*result = NULL;
			return 1;
		}

		while (r + l > s) {
			struct ips *p = malloc(sizeof(*p));

			if (!p) {
				freeips(*result);
				free(r);
				return DNS_ERROR_LOCAL;
			}
			*q = p;
			p->next = NULL;
			p->addr.s6_addr32[0] = 0;
			p->addr.s6_addr32[1] = 0;
			p->addr.s6_addr32[2] = htonl(0xffff);
			memcpy(&(p->addr.s6_addr32[3]), s, 4);

			q = &(p->next);
			s += 4;
		}
	}

	free(r);
	return l ? 0 : 1;
}

/**
 * \brief get host name for IP address
 *
 * @param ip the IP to look up
 * @param result name will be stored here
 * @return how many names were found, negative on error
 * @retval 0 host not found
 * @retval -1 local error (e.g. ENOMEM)
 * @retval -2 temporary DNS error
 * @retval -3 permanent DNS error
 */
int
ask_dnsname(const struct in6_addr *ip, char **result)
{
	int r;

	r = dnsname(result, ip);

	if (!r)
		return *result ? 1 : 0;

	switch (errno) {
	case ETIMEDOUT:
	case EAGAIN:
		return DNS_ERROR_TEMP;
	case ENFILE:
	case EMFILE:
	case ENOBUFS:
		errno = ENOMEM;
		/* fallthrough */
	case ENOMEM:
		return DNS_ERROR_LOCAL;
	case ENOENT:
		return 0;
	default:
		return DNS_ERROR_PERM;
	}
}
