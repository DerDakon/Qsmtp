#include <libowfatconn.h>
#include <qdns.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct {
	const char *name;
	const char *ip;
} dns_entries[] = {
	{
		.name = "first.a.example.net",
		.ip = "::ffff:10.0.0.1"
	},
	{
		.name = "second.a.example.net",
		.ip = "::ffff:10.0.0.2"
	},
	{
		.name = "second.a.example.net",
		.ip = "::ffff:10.0.2.2"
	},
	{
		.name = "third.a.example.net",
		.ip = "::ffff:10.0.0.3"
	},
	{
		.name = "third.a.example.net",
		.ip = "::ffff:10.0.3.3"
	},
	{
		.name = "third.a.example.net",
		.ip = "::ffff:10.3.3.3"
	},
	{
		.name = "first.aaaa.example.net",
		.ip = "abcd::ffff:10:1"
	},
	{
		.name = "second.aaaa.example.net",
		.ip = "abcd::ffff:10:2"
	},
	{
		.name = "second.aaaa.example.net",
		.ip = "abcd::ffff:10:22"
	},
	{
		.name = "third.aaaa.example.net",
		.ip = "abcd::ffff:10:3"
	},
	{
		.name = "third.aaaa.example.net",
		.ip = "abcd::ffff:10:33"
	},
	{
		.name = "third.aaaa.example.net",
		.ip = "abcd::ffff:10:333"
	},
	{ }
};

static const char timeouthost[] = "timeout.example.com";
static const char timeoutmx[] = "timeoutmx.example.com";

static int
findip(const char *name, struct in6_addr *addr, int start)
{
	int i = start;

	if ((strcmp(name, timeouthost) == 0) || (strcmp(name, timeoutmx) == 0)) {
		errno = ETIMEDOUT;
		return -1;
	}

	while (dns_entries[i].name != NULL) {
		if (strcmp(dns_entries[i].name, name) == 0) {
			if (inet_pton(AF_INET6, dns_entries[i].ip, addr) != 1) {
				fprintf(stderr, "%s can not be parsed as IPv6 address\n", dns_entries[i].ip);
				exit(EINVAL);
			}
			return i;
		}
		i++;
	}

	errno = ENOENT;
	return -1;
}

int dnsip4(char **out, size_t *len, const char *host)
{
	struct in6_addr addr;

	*out = NULL;
	*len = 0;

	int r = findip(host, &addr, 0);
	if (r < 0)
		return r;

	do {
		char *n;

		if (!IN6_IS_ADDR_V4MAPPED(&addr)) {
			r = findip(host, &addr, r + 1);
			continue;
		}

		n = realloc(*out, *len + 4);
		if (n == NULL) {
			free(*out);
			*out = NULL;
			*len = 0;
			errno = ENOMEM;
			return -1;
		}
		*out = n;

		memcpy(*out + *len, &addr.s6_addr32[3], 4);

		*len += 4;

		r = findip(host, &addr, r + 1);
	} while (r > 0);

	if ((errno != ENOENT) || (*len == 0)) {
		int e = errno;
		free(*out);
		*out = NULL;
		*len = 0;
		errno = e;
		return -1;
	}

	return 0;
}

int dnsip6(char **out, size_t *len, const char *host)
{
	struct in6_addr addr;

	*out = NULL;
	*len = 0;

	int r = findip(host, &addr, 0);
	if (r < 0)
		return r;

	do {
		char *n;

		n = realloc(*out, *len + 16);
		if (n == NULL) {
			free(*out);
			*out = NULL;
			*len = 0;
			errno = ENOMEM;
			return -1;
		}
		*out = n;

		memcpy(*out + *len, &addr, 16);

		*len += 16;

		r = findip(host, &addr, r + 1);
	} while (r > 0);

	if ((errno != ENOENT) || (*len == 0)) {
		int e = errno;
		free(*out);
		*out = NULL;
		*len = 0;
		errno = e;
		return -1;
	}

	return 0;
}

int dnstxt(char **out __attribute__((unused)), const char *host __attribute__((unused)))
{
	errno = ENOENT;
	return -1;
}

#define MAX_MX_PER_DOMAIN 3
static struct {
	const char *name;
	struct {
		unsigned int dnsindex; /* index into dns_entries */
		uint16_t priority;
	} entries[MAX_MX_PER_DOMAIN];
} mxentries[] = {
	/* one host, three hosts */
	{
		.name = "mx.example.com",
		.entries = {
			{
				.dnsindex = 0,
				.priority = 10
			},
			{
				.dnsindex = 3,
				.priority = 20
			}
		}
	},
	/* two hosts, three hosts */
	{
		.name = "mx2.example.com",
		.entries = {
			{
				.dnsindex = 1,
				.priority = 10
			},
			{
				.dnsindex = 3,
				.priority = 20
			}
		}
	},
	/* one single host */
	{
		.name = "mx3.example.com",
		.entries = {
			{
				.dnsindex = 0,
				.priority = 10
			}
		}
	},
	/* three hosts, one host */
	{
		.name = "mx4.example.com",
		.entries = {
			{
				.dnsindex = 3,
				.priority = 10
			},
			{
				.dnsindex = 0,
				.priority = 20
			}
		}
	},
	/* two single host */
	{
		.name = "mx5.example.com",
		.entries = {
			{
				.dnsindex = 0,
				.priority = 10
			},
			{
				.dnsindex = 6,
				.priority = 20
			}
		}
	},
	/* 3-3-2 */
	{
		.name = "mx6.example.com",
		.entries = {
			{
				.dnsindex = 3,
				.priority = 10
			},
			{
				.dnsindex = 9,
				.priority = 20
			},
			{
				.dnsindex = 0,
				.priority = 30
			}
		}
	},
	{ }
};

int dnsmx(char **out, size_t *len, const char *host)
{
	*len = 0;

	for (unsigned int mxidx = 0; mxentries[mxidx].name != NULL; mxidx++) {
		if (strcmp(host, mxentries[mxidx].name) == 0) {
			char *o;
			unsigned int k;

#define has_entry(m, i) \
	((mxentries[m].entries[i].dnsindex != 0) || \
			(mxentries[m].entries[i].priority != 0))

			for (k = 0; k < MAX_MX_PER_DOMAIN; k++)
				if (has_entry(mxidx, k))
					*len += strlen(dns_entries[mxentries[mxidx].entries[k].dnsindex].name) + 3;

			*out = malloc(*len);
			if (*out == NULL)
				return -1;

			o = *out;
			for (k = 0; k < MAX_MX_PER_DOMAIN; k++)
				if (has_entry(mxidx, k)) {
					size_t namelen = strlen(dns_entries[mxentries[mxidx].entries[k].dnsindex].name);
					uint16_t p = htons(mxentries[mxidx].entries[k].priority);
					memcpy(o, &p, sizeof(p));
					o += sizeof(p);
					memcpy(o, dns_entries[mxentries[mxidx].entries[k].dnsindex].name, namelen + 1);
					o += namelen + 1;
				}

			return 0;
#undef has_entry
		}
	}

	if (strcmp(host, timeouthost) == 0) {
		errno = ETIMEDOUT;
		return -1;
	} else if (strcmp(host, timeoutmx) == 0) {
		unsigned short *alsoout;

		*len = strlen(timeoutmx) + 3;
		*out = malloc(*len);

		if (*out == NULL)
			return -1;

		alsoout = (unsigned short *)*out;
		*alsoout = htons(10);

		memcpy(*out + 2, timeoutmx, strlen(timeoutmx) + 1);
		return 0;
	} else {
		errno = ENOENT;
		return -1;
	}
}

int dnsname(char **out, const struct in6_addr *ip)
{
	char ipstr[INET6_ADDRSTRLEN];
	int i = 0;

	inet_ntop(AF_INET6, ip, ipstr, sizeof(ipstr));

	while (dns_entries[i].name != NULL) {
		if (strcmp(dns_entries[i].ip, ipstr) == 0) {
			*out = strdup(dns_entries[i].name);
			if (*out == NULL)
				return -1;

			return 0;
		}
		i++;
	}

	errno = ENOENT;
	return -1;
}

static int
test_fwdrev(void)
{
	int err = 0;
	unsigned int idx = 0;

	while (dns_entries[idx].name != NULL) {
		struct in6_addr *res = NULL;

		if ((idx > 0) && (strcmp(dns_entries[idx - 1].name, dns_entries[idx].name) == 0)) {
			idx++;
			continue;
		}

		int cnt = ask_dnsa(dns_entries[idx].name, &res);
		if (cnt <= 0) {
			cnt = ask_dnsaaaa(dns_entries[idx].name, &res);
			if (cnt <= 0) {
				fprintf(stderr, "%s has returned neither IPv4 nor IPv6 address\n", dns_entries[idx].name);
				err++;
				idx++;
				continue;
			}
		} else {
			const int cntnr = ask_dnsa(dns_entries[idx].name, NULL);
			if (cntnr != cnt) {
				fprintf(stderr, "ask_dnsa(%s) returned different results with (%i) and without (%i) result pointer\n",
						dns_entries[idx].name, cnt, cntnr);
				err++;
			}
		}

		struct in6_addr *cur = res;
		while (cnt > 0) {
			char *nname = NULL;

			if (ask_dnsname(cur, &nname) <= 0) {
				fprintf(stderr, "no reverse lookup found for IP of %s\n", dns_entries[idx].name);
				err++;
			} else {
				if (strcmp(nname, dns_entries[idx].name) != 0) {
					fprintf(stderr, "reverse lookup %s different from %s\n", nname, dns_entries[idx].name);
					err++;
				}
				free(nname);
			}

			cur++;
			cnt--;
		}

		free(res);
		idx++;
	}

	return err;
}

static int
test_implicit_mx(void)
{
	int err = 0;
	unsigned int idx = 0;

	while (dns_entries[idx].name != NULL) {
		struct ips *cur;

		if ((idx > 0) && (strcmp(dns_entries[idx - 1].name, dns_entries[idx].name) == 0)) {
			idx++;
			continue;
		}

		struct ips *res = (void *)((uintptr_t)-1);

		if (ask_dnsmx(dns_entries[idx].name, &res) != 0) {
			fprintf(stderr, "%s did not return implicit MX entries\n", dns_entries[idx].name);
			err++;
			idx++;
			continue;
		}

		cur = res;
		while (cur != NULL) {
			char *nname = NULL;
			unsigned short s;

			if (cur->priority != MX_PRIORITY_IMPLICIT) {
				fprintf(stderr, "MX priority for %s was not set to MX_PRIORITY_IMPLICIT (%u), but %u\n",
						dns_entries[idx].name, MX_PRIORITY_IMPLICIT, cur->priority);
				err++;
			}

			if (ask_dnsname(cur->addr, &nname) <= 0) {
				fprintf(stderr, "no reverse lookup found for implicit MX IP of %s\n", dns_entries[idx].name);
				err++;
			} else if (strcmp(cur->name, dns_entries[idx].name) != 0) {
				fprintf(stderr, "MX name for %s was %s\n", dns_entries[idx].name, cur->name);
				free(nname);
				err++;
			} else {
				free(nname);
			}

			for (s = 0; s < cur->count; s++) {
				if (ask_dnsname(cur->addr + s, &nname) <= 0) {
					fprintf(stderr, "no reverse lookup found for implicit MX #%u IP of %s\n", s, dns_entries[idx].name);
					err++;
				} else {
					if (strcmp(nname, dns_entries[idx].name) != 0) {
						fprintf(stderr, "reverse lookup %s of IP %u different from %s\n", nname, s, dns_entries[idx].name);
						err++;
					}
					free(nname);
				}
			}

			cur = cur->next;
		}

		freeips(res);
		idx++;
	}

	return err;
}

static int
test_mx(void)
{
	int err = 0;

	for (unsigned int mxidx = 0; mxentries[mxidx].name != NULL; mxidx++) {
		struct ips *res = (void *)((uintptr_t)-1);
		unsigned int idx = 0;

		if (ask_dnsmx(mxentries[mxidx].name, &res) != 0) {
			fprintf(stderr, "lookup of %s did not return MX entries\n", mxentries[mxidx].name);
			return ++err;
		}

		struct ips *cur = res;
		while (cur != NULL) {
			char *nname = NULL;
			const char *ename = NULL;
			unsigned int k;

			/* status output */
			printf("%s: MX[%u:%u]: name %s prio %u\n", __func__, mxidx, idx, cur->name, cur->priority);

			if (cur->name == NULL) {
				fprintf(stderr, "MX[%u:%u] lookup has no name set\n", mxidx, idx);
				err++;
				idx++;
				cur = cur->next;
				continue;
			}

			/* find the host name belonging to this entry */
			for (k = 0; k < MAX_MX_PER_DOMAIN; k++)
				if (mxentries[mxidx].entries[k].priority == cur->priority) {
					ename = dns_entries[mxentries[mxidx].entries[k].dnsindex].name;
					break;
				}

			if (ename == NULL) {
				fprintf(stderr, "MX[%u:%u] lookup has unexpected priority %u\n", mxidx, idx, cur->priority);
				err++;
				idx++;
				cur = cur->next;
				continue;
			}

			if (strcmp(cur->name, ename) != 0) {
				fprintf(stderr, "MX[%u:%u] lookup has wrong name %s set, expected was %s\n", mxidx, idx, cur->name, ename);
				err++;
			}

			for (k = 0; k < cur->count; k++) {
				char ipbuf[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, cur->addr + k, ipbuf, sizeof(ipbuf));
				unsigned short l;

				printf("%s: MX[%u:%u:%u]: name %s prio %u IP %s\n", __func__, mxidx, idx, k, cur->name, cur->priority, ipbuf);
				/* check reverse lookup of every IP */
				if (ask_dnsname(cur->addr + k, &nname) <= 0) {
					fprintf(stderr, "MX[%u:%u:%u] no reverse lookup found for MX IP\n", mxidx, idx, k);
					err++;
				} else {
					free(nname);
				}

				/* check that every IP is only returned once per MX name */
				for (l = 0; l < k; l++)
					if (IN6_ARE_ADDR_EQUAL(cur->addr + k, cur->addr + l)) {
						fprintf(stderr, "MX[%u:%u:%u] has same address as MX[%u:%u:%u]\n",
								mxidx, idx, k, mxidx, idx, l);
						err++;
					}
			}

			cur = cur->next;
			idx++;
		}

		freeips(res);
	}

	return err;
}

static int
test_errors(void)
{
	int err = 0;
	struct ips *i = NULL;

	int r = ask_dnsmx(timeouthost, &i);
	if ((r != DNS_ERROR_TEMP) || (errno != ETIMEDOUT)) {
		fprintf(stderr, "lookup of %s returned %i, errno %i\n", timeouthost, r, errno);
		freeips(i);
		err++;
	}

	i = NULL;
	r = ask_dnsmx(timeoutmx, &i);
	if ((r != DNS_ERROR_TEMP) || (errno != ETIMEDOUT)) {
		fprintf(stderr, "lookup of %s returned %i, errno %i\n", timeouthost, r, errno);
		freeips(i);
		err++;
	}

	return err;
}

/**
 * @brief test the FOREACH_STRUCT_IPS macro
 */
static int
test_foreach(void)
{
	struct in6_addr a[8];
	struct ips ip[5] = {
		{
			.priority = 1,
			.count = 1,
		},
		{
			.priority = 2,
			.count = 3,
		},
		{
			.priority = 3,
			.count = 1,
		},
		{
			.priority = 4,
			.count = 1,
		},
		{
			.priority = 5,
			.count = 2
		}
	};
	struct ips *cur;
	unsigned short s;
	int err = 0;

	memset(a, 0, sizeof(a));

	for (s = 0; s < sizeof(a) / sizeof(a[0]); s++)
		a[s].s6_addr32[0] = s + 1;

	ip[0].addr = a;
	for (s = 0; s < sizeof(ip) / sizeof(ip[0]) - 1; s++) {
		ip[s + 1].addr = ip[s].addr + ip[s].count;
		ip[s].next = ip + s + 1;
	}

	uint32_t u = 0;
	/* now iterate over all IPs, check that their lower value gives the
	 * expected sequence 1..8. Set the next value to the priority, so that
	 * can be checked later. */

	FOREACH_STRUCT_IPS(cur, s, ip) {
		if (cur->addr[s].s6_addr32[0] != u + 1) {
			fprintf(stderr, "index %u: s %u, IP index was %u\n",
					u, s, cur->addr[s].s6_addr32[0]);
			err++;
		}
		u++;
		cur->addr[s].s6_addr32[1] = cur->priority;
	}

	for (s = 0; s < sizeof(a) / sizeof(a[0]); s++) {
		const uint32_t exp[] = { 1, 2, 2, 2, 3, 4, 5, 5 };

		assert(sizeof(a) / sizeof(a[0]) == sizeof(exp) / sizeof(exp[0]));

		if (a[s].s6_addr32[1] != exp[s]) {
			fprintf(stderr, "IP %u has priority %u but %u was expected\n",
					s, a[s].s6_addr32[1], exp[s]);
			err++;
		}
	}

	return err;
}

int
main(void)
{
	int err = 0;

	err += test_fwdrev();
	err += test_implicit_mx();
	err += test_mx();
	err += test_errors();
	err += test_foreach();

	return err;
}
