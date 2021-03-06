/** \file qdns.c
 \brief DNS query functions
 */

#include <qdns.h>

#include <libowfatconn.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * \brief get info out of the DNS
 *
 * \param name the name to look up
 * \param result first element of a list of results will be placed
 * \retval  0 on success
 * \retval  1 if host is not existent
 * \retval  2 null MX is set for this domain (RfC 7505)
 * \retval DNS_ERROR_TEMP if temporary DNS error
 * \retval DNS_ERROR_PERM if permanent DNS error
 * \retval DNS_ERROR_LOCAL on error (errno is set)
 */
int
ask_dnsmx(const char *name, struct ips **result)
{
	char *r;
	size_t l;
	int errtype = 0;

	int i = dnsmx(&r, &l, name);

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

	/* there is no MX record, so we look for an AAAA record */
	if (!l) {
		struct in6_addr *a;

		int rc = ask_dnsaaaa(name, &a);

		if (rc < 0)
			return rc;
		else if (rc == 0)
			return 1;

		/* the DNS priority is 2 bytes long so MX_PRIORITY_IMPLICIT
		 * (i.e. 65536) can never be returned from a real DNS_MX lookup */
		*result = in6_to_ips(a, rc, MX_PRIORITY_IMPLICIT);
		if (*result == NULL)
			return DNS_ERROR_LOCAL;

		(*result)->name = strdup(name);
		if ((*result)->name == NULL) {
			freeips(*result);
			return DNS_ERROR_LOCAL;
		}

		return 0;
	}

	*result = NULL;

	/* RfC 7505 null MX: a single entry, any priority, only '.' */
	if (l == 4 && r[2] == '.') {
		free(r);
		return 2;
	}

	char *s = r;
	while (r + l > s) {
		struct in6_addr *a;
		int rc;
		const char *mxname = s + 2;

		rc = ask_dnsaaaa(mxname, &a);
		if (rc == DNS_ERROR_LOCAL) {
			freeips(*result);
			free(r);
			if (errno == ENOMEM)
				return DNS_ERROR_LOCAL;
			return DNS_ERROR_TEMP;
		} else if (rc > 0) {
			uint16_t pr;	/* priority */
			struct ips *u;

			/* must be done with memcpy() as s may have arbitrary alignment */
			memcpy(&pr, s, sizeof(pr));
			u = in6_to_ips(a, rc, ntohs(pr));

			/* add the new results to the list */
			if (u == NULL) {
				freeips(*result);
				free(r);
				return DNS_ERROR_LOCAL;
			}

			u->next = *result;
			*result = u;

			u->name = strdup(mxname);
			if (u->name == NULL) {
				freeips(*result);
				free(r);
				return DNS_ERROR_LOCAL;
			}
		} else if (rc != 0) {
			errtype = (1 << -rc);
		}
		/* 2 for priority, one for terminating \0 */
		s += 3 + strlen(mxname);
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
 * \retval  0 no entries found
 * \retval >0 how many entries were returned in result
 * \retval DNS_ERROR_TEMP if temporary DNS error
 * \retval DNS_ERROR_PERM if permanent DNS error
 * \retval DNS_ERROR_LOCAL on error (errno is set)
 */
int
ask_dnsaaaa(const char *name, struct in6_addr **result)
{
	int i;
	char *r;
	size_t l;
	char *s;
	unsigned int cnt = 0;

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
			return 0;
		default:
			return DNS_ERROR_PERM;
		}
	}

	s = r;

	if (!l)
		return 0;

	*result = malloc(((l + 15) / 16) * sizeof(**result));
	if (*result == NULL) {
		free(r);
		return DNS_ERROR_LOCAL;
	}

	for (cnt = 0; r + l > s; s += sizeof(**result))
		memcpy(*result + cnt++, s, 16);

	free(r);
	return cnt;
}

/**
 * @brief get A record from of the DNS
 * @param name the name to look up
 * @param result first element of a list of results will be placed, or NULL if only return code is of interest
 * @return if records have been found
 * \retval  0 no entries found
 * \retval >0 how many entries were returned in result
 * @retval DNS_ERROR_LOCAL on error (errno is set)
 * @retval DNS_ERROR_TEMP temporary DNS error
 * @retval DNS_ERROR_PERM permanent DNS error
 */
int
ask_dnsa(const char *name, struct in6_addr **result)
{
	int i;
	char *r;
	size_t l;
	unsigned int idx = 0;

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
			return 0;
		default:
			return DNS_ERROR_PERM;
		}
	}

	if (l == 0)
		return 0;

	if (result) {
		char *s = r;
		*result = malloc(((l + 3) / 4) * sizeof(**result));
		if (*result == NULL) {
			free(r);
			return DNS_ERROR_LOCAL;
		}

		while (r + l > s) {
			struct in_addr ip4;
			memcpy(&(ip4.s_addr), s, sizeof(ip4.s_addr));
			(*result)[idx] = in_addr_to_v4mapped(&ip4);

			s += 4;
			idx++;
		}
	} else {
		idx = l / 4;
	}

	free(r);
	return idx;
}

/**
 * \brief get host name for IP address
 *
 * @param ip the IP to look up
 * @param result name will be stored here
 * @return how many names were found, negative on error
 * @retval 0 host not found
 * @retval DNS_ERROR_LOCAL local error (errno is set)
 * @retval DNS_ERROR_TEMP temporary DNS error
 * @retval DNS_ERROR_PERM permanent DNS error
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
