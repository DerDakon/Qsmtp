#include "qdns.h"
#include "libowfatconn.h"

#include <errno.h>
#include <arpa/inet.h> 
#include <stdio.h>
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
	{
		.name = NULL
	}
};

static int
findip(const char *name, struct in6_addr *addr, int start)
{
	int i = start;

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

int dnsip4(char **out, unsigned int *len, const char *host)
{
	int r;
	struct in6_addr addr;

	*out = NULL;
	*len = 0;

	r = findip(host, &addr, 0);
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

int dnsip6(char **out, unsigned int *len, const char *host)
{
	int r;
	struct in6_addr addr;

	*out = NULL;
	*len = 0;

	r = findip(host, &addr, 0);
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

int dnsmx(char **out __attribute__((unused)), unsigned int *len __attribute__((unused)), const char *host __attribute__((unused)))
{
	errno = ENOENT;
	return -1;
}

int dnsname(char **out, const char *ip)
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
	struct ips *res;

	while (dns_entries[idx].name != NULL) {
		struct ips *cur;

		if ((idx > 0) && (strcmp(dns_entries[idx - 1].name, dns_entries[idx].name) == 0)) {
			idx++;
			continue;
		}

		res = NULL;

		if (ask_dnsa(dns_entries[idx].name, &res) != 0) {
			if (ask_dnsaaaa(dns_entries[idx].name, &res) != 0) {
				fprintf(stderr, "%s has returned neither IPv4 nor IPv6 address\n", dns_entries[idx].name);
				err++;
				idx++;
				continue;
			}
		}

		cur = res;
		while (cur != NULL) {
			char *nname = NULL;

			if (ask_dnsname(&cur->addr, &nname) <= 0) {
				fprintf(stderr, "no reverse lookup found for IP of %s\n", dns_entries[idx].name);
				err++;
			} else {
				if (strcmp(nname, dns_entries[idx].name) != 0) {
					fprintf(stderr, "reverse lookup %s different from %s\n", nname, dns_entries[idx].name);
					err++;
				}
				free(nname);
			}

			cur = cur->next;
		}

		freeips(res);
		idx++;
	}

	return err;
}

static int
test_implicit_mx(void)
{
	int err = 0;
	unsigned int idx = 0;
	struct ips *res;

	while (dns_entries[idx].name != NULL) {
		struct ips *cur;

		if ((idx > 0) && (strcmp(dns_entries[idx - 1].name, dns_entries[idx].name) == 0)) {
			idx++;
			continue;
		}

		res = NULL;

		if (ask_dnsmx(dns_entries[idx].name, &res) != 0) {
			fprintf(stderr, "%s did not return implicit MX entries\n", dns_entries[idx].name);
			err++;
			idx++;
			continue;
		}

		cur = res;
		while (cur != NULL) {
			char *nname = NULL;

			if (cur->priority != 65536) {
				fprintf(stderr, "MX priority for %s was not set to 65536, but %u\n", dns_entries[idx].name, cur->priority);
				err++;
			}

			if (ask_dnsname(&cur->addr, &nname) <= 0) {
				fprintf(stderr, "no reverse lookup found for implicit MX IP of %s\n", dns_entries[idx].name);
				err++;
			} else {
				if (strcmp(nname, dns_entries[idx].name) != 0) {
					fprintf(stderr, "reverse lookup %s different from %s\n", nname, dns_entries[idx].name);
					err++;
				}
				free(nname);
			}

			cur = cur->next;
		}

		freeips(res);
		idx++;
	}

	return err;
}

int
main(void)
{
	int err = 0;

	err += test_fwdrev();
	err += test_implicit_mx();

	return err;
}
