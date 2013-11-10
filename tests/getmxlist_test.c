#include "qremote.h"
#include <conn.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct ips *
smtproute(const char *a, const size_t b, unsigned int *c)
{
	(void) a;
	(void) b;
	(void) c;
	return NULL;
}

ssize_t
write_status(const char *str)
{
	return write(1, str, strlen(str) + 1);

	exit(EFAULT);
}

void
err_mem(const int doquit)
{
	(void) doquit;

	write_status("Z4.3.0 Out of memory.\n");

	exit(ENOMEM);
}

int
main(void)
{
	struct {
		const char *input;
		const char *expect;
		unsigned int prio;
	} patterns[] = {
		{
			.input = "127.0.0.1",
			.expect = "::ffff:127.0.0.1",
			.prio = 0
		},
		{
			.input = "::1",
			.expect = "::1",
#ifdef IPV4ONLY
			.prio = 65537
#else
			.prio = 0
#endif
		},
		{
			.input = NULL,
			.expect = NULL,
			.prio = 0
		}
	};
	unsigned int i;
	int ret = 0;

	for (i = 0; patterns[i].input != NULL; i++) {
		struct ips *mx = NULL;
		struct in6_addr addr;
		char buf[32];

		snprintf(buf, sizeof(buf), "[%s]", patterns[i].input);

		getmxlist(buf, &mx);

		if (inet_pton(AF_INET6, patterns[i].expect, &addr) <= 0)
			exit(EFAULT);

		if (mx == NULL) {
			fprintf(stderr, "%s was not parsed\n",
					patterns[i].input);
			ret++;
			continue;
		}

		if (mx->next != NULL) {
			fprintf(stderr, "addr %u returned multiple IPs\n",
					i);
			ret++;
			freeips(mx);
			continue;
		}

		if (memcmp(&addr, &mx->addr, sizeof(addr)) != 0) {
			fprintf(stderr, "addr %u was not parsed to correct result\n",
					i);
			ret++;
			freeips(mx);
			continue;
		}

		if (patterns[i].prio != mx->priority) {
			fprintf(stderr, "addr %u: found priority %u, expected %u\n",
					i, mx->priority, patterns[i].prio);
			ret++;
			freeips(mx);
			continue;
		}

		freeips(mx);
	}

	return ret;
}
