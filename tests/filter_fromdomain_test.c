#include "userfilters.h"
#include "test_io/testcase_io.h"

#include "qsmtpd.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

struct xmitstat xmitstat;
unsigned int goodrcpt;
struct recip *thisrecip;
const char **globalconf;

extern int cb_fromdomain(const struct userconf *ds, char **logmsg, int *t);

static int err;

static int
test_net_writen(const char * const * msg)
{
	unsigned int i;

	for (i = 0; msg[i]; i++)
		printf("%s", msg[i]);

	return 0;
}

static int
test_netwrite(const char *msg)
{
	printf("%s", msg);
	return 0;
}

static struct userconf ds;

static int
check_expect(const int r_expect, const char *errmsg)
{
	int r;
	int t = -1;
	char *logmsg = NULL;

	r = cb_fromdomain(&ds, &logmsg, &t);
	if (r == r_expect)
		return 0;

	fprintf(stderr, "%s\n", errmsg);
	fprintf(stderr, "cb_fromdomain() should have returned %i but returned %i, message '%s', t %i\n",
			r_expect, r, logmsg, t);

	return 1;
}

/* set up this IP as sender and MX ip */
static void
setup_ip(const char *ip)
{
	int r;

	strcpy(xmitstat.remoteip, ip);
	r = inet_pton(AF_INET6, xmitstat.remoteip, &xmitstat.sremoteip);
	assert(r == 1);

	xmitstat.ipv4conn = IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip);

	if (xmitstat.frommx == NULL)
		return;

	xmitstat.fromdomain = 0;
	xmitstat.frommx->addr = xmitstat.sremoteip;
	xmitstat.frommx->priority = 42;
	xmitstat.frommx->next = NULL;
}

int main()
{
	char configline[32];
	char *configarray[] = {
		configline,
		NULL
	};
	struct ips frommx;

	testcase_setup_net_writen(test_net_writen);
	testcase_setup_netwrite(test_netwrite);

	memset(&ds, 0, sizeof(ds));
	globalconf = NULL;

	ds.userconf = configarray;
	sprintf(configline, "fromdomain=0");

	err += check_expect(0, "checking empty fromdomain");

	xmitstat.mailfrom.s = "foo@example.org";
	xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);

	err += check_expect(0, "checking deactivated fromdomain filter");

	sprintf(configline, "fromdomain=4");
	setup_ip("::ffff:172.16.42.42");

	err += check_expect(0, "checking local net 172.16.42.42 without MX");

	xmitstat.frommx = &frommx;
	setup_ip("::ffff:172.16.42.42");

	err += check_expect(1, "checking local net 172.16.42.42");

	sprintf(configline, "fromdomain=1");

	xmitstat.fromdomain = 1;
	xmitstat.frommx = NULL;
	err += check_expect(1, "checking no MX");

	sprintf(configline, "fromdomain=7");
	xmitstat.frommx = &frommx;
	setup_ip("::ffff:62.27.20.61");
	err += check_expect(0, "checking mail.sf-mail.de");

	sprintf(configline, "fromdomain=2");
	setup_ip("::ffff:127.4.5.6");
	err += check_expect(1, "checking IPv4 loopback net");

	sprintf(configline, "fromdomain=2");
	setup_ip("::1");
	err += check_expect(1, "checking IPv6 loopback net");

	sprintf(configline, "fromdomain=4");
	setup_ip("feab::42:42:42");
	err += check_expect(1, "checking IPv6 link local net");

	return err;
}
