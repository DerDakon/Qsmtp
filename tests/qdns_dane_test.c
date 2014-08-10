#include <qdns_dane.h>

#include <qdns.h>

#include <assert.h>
#include <dns.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int err;

int dns_domain_fromdot(char **q __attribute__ ((unused)), const char * host, unsigned int len)
{
	if (len != strlen(host))
		err++;

	if (strcmp(host, "_42._tcp.foo.example.org") != 0)
		err++;

	return 0;
}

int
main(void)
{
	struct daneinfo *val = (struct daneinfo *)(uintptr_t)-1;

	if (dnstlsa("foo.example.org", 42, NULL) != DNS_ERROR_LOCAL)
		err++;

	if (dnstlsa("foo.example.org", 42, &val) != DNS_ERROR_LOCAL)
		err++;

	if (val != NULL)
		err++;

	return err;
}
