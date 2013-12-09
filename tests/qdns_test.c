#include "qdns.h"
#include "libowfatconn.h"

#include <errno.h>
#include <arpa/inet.h> 
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
	{
		.name = NULL
	}
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

int dnsip6(char **out, size_t *len, const char *host)
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

static const char mxname[] = "mx.example.com";

int dnsmx(char **out, size_t *len, const char *host)
{
	*len = 0;

	if (strcmp(host, mxname) == 0) {
		unsigned short *alsoout;

		*len = 4 + strlen(dns_entries[0].name) + strlen(dns_entries[4].name) + 2;
		*out = malloc(*len);
		if (*out == NULL)
			return -1;

		alsoout = (unsigned short *)*out;
		*alsoout = htons(10);
		memcpy(*out + 2, dns_entries[0].name, strlen(dns_entries[0].name) + 1);
		alsoout = (unsigned short *)(*out + strlen(dns_entries[0].name) + 3);
		*alsoout = htons(20);
		memcpy(*out + 5 + strlen(dns_entries[0].name), dns_entries[4].name, strlen(dns_entries[4].name) + 1);

		return 0;
	} else if (strcmp(host, timeouthost) == 0) {
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
	}

	errno = ENOENT;
	return -1;
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

static int
test_mx(void)
{
	int err = 0;
	struct ips *res = NULL;
	struct ips *cur;

	if (ask_dnsmx(mxname, &res) != 0) {
		fprintf(stderr, "lookup of %s did not return MX entries\n", mxname);
		return ++err;
	}

	cur = res;
	while (cur != NULL) {
		char *nname = NULL;

		if (ask_dnsname(&cur->addr, &nname) <= 0) {
			fprintf(stderr, "no reverse lookup found for MX IP\n");
			err++;
		} else {
			if (strcmp(nname, dns_entries[0].name) == 0) {
				if (cur->priority != 10) {
					fprintf(stderr, "MX entries for %s should have priority 10, but have %u\n", nname, cur->priority);
					err++;
				}
			} else 	if (strcmp(nname, dns_entries[4].name) == 0) {
				if (cur->priority != 20) {
					fprintf(stderr, "MX entries for %s should have priority 20, but have %u\n", nname, cur->priority);
					err++;
				}
			} else {
				fprintf(stderr, "unexpected reverse lookup %s for MX priority %u\n", nname, cur->priority);
				err++;
			}

			free(nname);
		}

		cur = cur->next;
	}
	
	freeips(res);

	return err;
}

static int
test_errors(void)
{
	int err = 0;
	int r;
	struct ips *i = NULL;

	r = ask_dnsmx(timeouthost, &i);
	if ((r != 2) || (errno != ETIMEDOUT)) {
		fprintf(stderr, "lookup of %s returned %i, errno %i\n", timeouthost, r, errno);
		err++;
	}

	r = ask_dnsmx(timeoutmx, &i);
	if ((r != 2) || (errno != ETIMEDOUT)) {
		fprintf(stderr, "lookup of %s returned %i, errno %i\n", timeouthost, r, errno);
		err++;
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

	return err;
}
