#include <qremote/conn.h>
#include <qremote/qremote.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct ips *
smtproute(const char *a __attribute__ ((unused)), const size_t b __attribute__ ((unused)),
		unsigned int *c __attribute__ ((unused)))
{
	return NULL;
}

void
write_status(const char *str)
{
	puts(str);

	exit(EFAULT);
}

void
write_status_m(const char **strs, const unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count - 1; i++)
		fputs(strs[i], stdout);

	write_status(strs[count - 1]);
}

void
err_mem(const int doquit __attribute__ ((unused)))
{
	(void) doquit;

	write_status("Z4.3.0 Out of memory.");

	exit(ENOMEM);
}

static int
test_tryconn(void)
{
	int ret = 0;
	struct ips mx[3];
	int i;

	memset(mx, 0, sizeof(mx));
	mx[0].next = mx + 1;
	mx[0].priority = MX_PRIORITY_USED;
	mx[0].addr = &mx[0].ad;
	mx[0].count = 1;
	mx[1].next = mx + 2;
	mx[1].priority = MX_PRIORITY_USED;
	mx[1].addr = &mx[1].ad;
	mx[1].count = 1;
	mx[2].priority = MX_PRIORITY_CURRENT;
	mx[2].addr = &mx[2].ad;
	mx[2].count = 1;

	i = tryconn(mx, NULL, NULL);
	if (i != -ENOENT) {
		fprintf(stderr, "tryconn() on exhausted MX list did return %i instead of %i (-ENOENT)\n",
				i, -ENOENT);
		if (i >= 0)
			close(i);
		ret++;
	}

	for (i = 0; i < (int)(sizeof(mx) / sizeof(mx[0])); i++) {
		if (mx[i].priority != MX_PRIORITY_USED) {
			fprintf(stderr, "mx[%i].priority == %u, expected was MX_PRIORITY_USED (%u)\n", i,
					mx[i].priority, MX_PRIORITY_USED);
			ret++;
		}
	}

	return ret;
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
			.prio = MX_PRIORITY_USED
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

		if (!IN6_ARE_ADDR_EQUAL(&addr, mx->addr)) {
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

	ret += test_tryconn();

	return ret;
}
