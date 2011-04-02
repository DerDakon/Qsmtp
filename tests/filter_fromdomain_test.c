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
		printf(msg[i]);

	return 0;
}

static int
test_netwrite(const char *msg)
{
	printf(msg);
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

int main()
{
	int r;
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
	strcpy(xmitstat.remoteip, "::ffff:172.16.42.42");
	r = inet_pton(AF_INET6, xmitstat.remoteip, &xmitstat.sremoteip);
	assert(r == 1);

	err += check_expect(0, "checking local net 172.16.42.42 without MX");

	frommx.addr = xmitstat.sremoteip;
	frommx.priority = 42;
	frommx.next = NULL;
	xmitstat.frommx = &frommx;

	err += check_expect(1, "checking local net 172.16.42.42");

	sprintf(configline, "fromdomain=1");

	xmitstat.fromdomain = 1;
	xmitstat.frommx = NULL;
	err += check_expect(1, "checking no MX");

	return err;
}
