#include <qremote/client.h>
#include <qremote/qremote.h>
#include <qdns.h>

#include "test_io/testcase_io.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define ipstr_example "2001:db8:17:f4:d3::4"
#define ipstr_fail "2001:db8:17:f4:d3::5"
#define ipstr_unknown "2001:db8:17:f4:d3::6"
#define name_example "example.net"

char *partner_fqdn;
char *rhost;
size_t rhostlen;

void
err_mem(const int k __attribute__((unused)))
{
	exit(ENOMEM);
}

int
netget(void)
{
	exit(EFAULT);
	return -1;
}

int
test_ask_dnsname(const struct in6_addr *ip, char **result)
{
	struct in6_addr iptmp;

	inet_pton(AF_INET6, ipstr_example, &iptmp);

	if (memcmp(ip, &iptmp, sizeof(iptmp)) == 0) {
		*result = strdup(name_example);
		if (*result == NULL)
			exit(ENOMEM);

		return 1;
	}

	inet_pton(AF_INET6, ipstr_fail, &iptmp);

	if (memcmp(ip, &iptmp, sizeof(iptmp)) == 0)
		return -2;
	else
		return 0;
}

static int
testcase_valid_return(void)
{
	struct ips mx[2];

	memset(&mx, 0, sizeof(mx));
	mx[0].next = mx + 1;
	mx[0].priority = 42;

	inet_pton(AF_INET6, ipstr_example, &(mx[1].addr));
	mx[1].priority = 65538;

	getrhost(mx);

	if ((partner_fqdn == NULL) || (rhost == NULL)) {
		fprintf(stderr, "%s: NULL value set\n", __func__);
		return 1;
	}

	if (strcmp(partner_fqdn, name_example) != 0) {
		fprintf(stderr, "%s: FQDN %s expected, but got %s\n", __func__,
				name_example, partner_fqdn);
		return 1;
	}

	if (strcmp(rhost, name_example " [" ipstr_example "]") != 0) {
		fprintf(stderr, "%s: got unexpected rhost '%s'\n", __func__,
				rhost);
		return 1;
	}

	return 0;
}

static int
testcase_noname(const char *ipstr)
{
	struct ips mx[2];

	memset(&mx, 0, sizeof(mx));
	mx[0].next = mx + 1;
	mx[0].priority = 42;

	inet_pton(AF_INET6, ipstr, &(mx[1].addr));
	mx[1].priority = 65538;

	getrhost(mx);

	if (rhost == NULL) {
		fprintf(stderr, "%s: NULL value set\n", __func__);
		return 1;
	}

	if (partner_fqdn != NULL) {
		fprintf(stderr, "%s: no FQDN expected, but got %s\n", __func__,
				partner_fqdn);
		return 1;
	}

	if ((strncmp(rhost + 1, ipstr, strlen(ipstr)) != 0) || (*rhost != '[') ||
			(rhost[strlen(ipstr) + 1] != ']')) {
		fprintf(stderr, "%s: got unexpected rhost '%s'\n", __func__,
				rhost);
		return 1;
	}

	return 0;
}

int
main(void)
{
	int ret = 0;

	testcase_setup_ask_dnsname(test_ask_dnsname);

	ret += testcase_valid_return();
	ret += testcase_noname(ipstr_unknown);
	ret += testcase_noname(ipstr_fail);

	free(partner_fqdn);
	free(rhost);

	return ret;
}
