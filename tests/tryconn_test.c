#include <qdns.h>
#include <qremote/conn.h>
#include <qremote/qremote.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

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
	for (unsigned int i = 0; i < count - 1; i++)
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

static int getrhost_permitted;

void
getrhost(const struct ips *m __attribute__ ((unused)), const unsigned short idx __attribute__ ((unused)))
{
	if (!getrhost_permitted)
		abort();
	getrhost_permitted = 0;
}

static int
test_exhausted(void)
{
	int ret = 0;
	struct ips mx[3] = {
		{
			.next = mx + 1,
			.priority = MX_PRIORITY_USED,
			.count = 1,
		},
		{
			.next = mx + 2,
			.priority = MX_PRIORITY_USED,
			.count = 1
		},
		{
			.priority = MX_PRIORITY_CURRENT,
			.count = 1
		}
	};

	int i = tryconn(mx, NULL, NULL);
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

static int
test_fork(unsigned int mxindex)
{
	struct in_addr l4 = {
		.s_addr = htonl(INADDR_LOOPBACK)
	};
	struct in6_addr loopback4 = in_addr_to_v4mapped(&l4);
#ifdef IPV4ONLY
	const int sfamily = AF_INET;
	struct sockaddr_in sa = {
		.sin_family = sfamily,
		.sin_addr = l4
	};
#else
	const int sfamily = AF_INET6;
	struct sockaddr_in6 sa = {
		.sin6_family = sfamily,
		.sin6_addr = in6addr_loopback
	};
#endif
	int s = socket(sfamily, SOCK_STREAM, 0);
	socklen_t salen = sizeof(sa);
	const char pingmsg[] = "ping";
	const char pongmsg[] = "pong";
	char rbuf[strlen(pingmsg) + 2];
	int r;

	if (s < 0) {
		printf("%s[%u]: server socket() error %i\n", __func__, mxindex, errno);
		return 1;
	}
	r = bind(s, (struct sockaddr *)&sa, sizeof(sa));
	if (r < 0) {
		printf("%s[%u]: server bind() error %i\n", __func__, mxindex, errno);
		close(s);
		return 1;
	}
	r = getsockname(s, (struct sockaddr *)&sa, &salen);
	if (r < 0) {
		printf("%s[%u]: server getsockname() error %i\n", __func__, mxindex, errno);
		close(s);
		return 1;
	}
#ifdef IPV4ONLY
	targetport = ntohs(sa.sin_port);
#else
	targetport = ntohs(sa.sin6_port);
#endif

	memset(rbuf, 0, sizeof(rbuf));
	pid_t child = fork();
	if (child < 0) {
		printf("fork() error: %s (%i)\n", strerror(errno), errno);
		close(s);
		return 1;
	}
	if (child == 0) {
		struct in6_addr mxaddr[2] = {
			in6addr_any,
			in6addr_any
		};
		struct ips mx = {
			.addr = mxaddr,
			.count = mxindex + 1
		};

		close(s);

		if (mxindex >= sizeof(mxaddr) / sizeof(mxaddr[0]))
			abort();

		mxaddr[mxindex] =
#ifdef IPV4ONLY
			loopback4;
#else
			in6addr_loopback;
#endif
		if (mxindex > 0)
			mx.priority = MX_PRIORITY_CURRENT;

		/* wait a moment so the server can call listen() on the socket */
		sleep(1);

		getrhost_permitted = 1;
		s = tryconn(&mx, &loopback4, &in6addr_loopback);
		if (s < 0) {
			printf("%s[%i]: tryconn() failed: %i\n", __func__, mxindex, s);
			r = 1;
		} else {
			ssize_t rlen = write(s, pingmsg, strlen(pingmsg));
			if ((size_t)rlen != strlen(pingmsg)) {
				printf("%s[%u]: client write error %zi (%i)\n", __func__, mxindex, rlen, errno);
				r = 1;
			}
			rlen = read(s, rbuf, sizeof(rbuf) - 1);
			rbuf[sizeof(rbuf) - 1] = '\0';
			if (((size_t)rlen != strlen(pongmsg)) || (memcmp(rbuf, pongmsg, rlen) != 0)) {
				printf("%s[%u]: client read error, got %s (len %zu)\n", __func__, mxindex, rbuf, rlen);
				r = 1;
			}
			close(s);
		}
		if (r == 0)
			printf("tryconn() on index %u succeeded\n", mxindex);
		exit(r);
	} else {
		r = listen(s, 1);
		int t = accept(s, (struct sockaddr *)&sa, &salen);
		if (t < 0) {
			printf("%s[%u]: server access() error %i\n", __func__, mxindex, errno);
			r = 1;
		} else {
			ssize_t rlen = read(t, rbuf, sizeof(rbuf) - 1);
			rbuf[sizeof(rbuf) - 1] = '\0';
			if (((size_t)rlen != strlen(pingmsg)) || (memcmp(rbuf, pingmsg, rlen) != 0)) {
				printf("%s[%u]: server read error, got %s (len %zu)\n", __func__, mxindex, rbuf, rlen);
				r = 1;
			} else {
				rlen = write(t, pongmsg, strlen(pongmsg));
				if ((size_t)rlen != strlen(pingmsg)) {
					printf("%s[%u]: server write error %zi (%i)\n", __func__, mxindex, rlen, errno);
					r = 1;
				}
			}
		}
		close(t);
		close(s);

		if (waitpid(child, &t, 0) != child) {
			printf("%s[%u]: server waitpid() error %i\n", __func__, mxindex, errno);
			r = 1;
		}
		if (!WIFEXITED(r) || (WEXITSTATUS(r) != 0)) {
			printf("%s[%u]: child error %i\n", __func__, mxindex, WEXITSTATUS(r));
			r = 1;
		}
	}

	return r;
}

int
main(void)
{
	unsigned int i;
	int  r = 0;

	r += test_exhausted();
	for (i = 0; i < 2; i++)
		r += test_fork(i);

	return r;
}
