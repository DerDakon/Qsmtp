/** \file addipbl.c
 \brief helper program to an an IPv4 or IPv6 host or net address to a IP list for Qsmtp's filters
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void err_mixed(void) __attribute__ ((noreturn));
static void err_syntax(const char *arg) __attribute__ ((noreturn));

void
err_mixed(void)
{
	fputs("error: IPv4 and IPv6 addresses cannot be mixed in the same file\n", stderr);
	exit(EINVAL);
}

void
err_syntax(const char *arg)
{
	fputs("invalid IP address in argument '", stderr);
	fputs(arg, stderr);
	fputs("'\n", stderr);
	exit(EINVAL);
}

int
main(int argc, char *argv[])
{
	int mode = 0;	/* IPv4 addresses */

	if (argc == 1) {
		fputs("Usage: ", stdout);
		fputs(argv[0], stdout);
		fputs(" file ip [ip ...]\n", stdout);
		return 1;
	}
	int fd = open(argv[1], O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1)
		return errno;

	/* Find out if these are IPv6 or IPv4 addresses. */
	for (int j = 2; j < argc; j++) {
		struct in6_addr ip;
		char cpbuf[INET6_ADDRSTRLEN + 1];
		const char *sl = strchr(argv[j], '/');
		size_t len;

		if (sl == NULL) {
			len = strlen(argv[j]);
		} else {
			len = ((uintptr_t)sl) - ((uintptr_t)argv[j]);
		}
		if (len >= sizeof(cpbuf) - 1)
			err_syntax(argv[j]);
		strncpy(cpbuf, argv[j], len);
		cpbuf[len] = '\0';

		if (inet_pton(AF_INET, cpbuf, &ip) == 1) {
			if (mode == 6)
				err_mixed();
			mode = 4;
		} else if (inet_pton(AF_INET6, cpbuf, &ip) == 1) {
			if (mode == 4)
				err_mixed();
			mode = 6;
		} else {
			err_syntax(argv[j]);
		}
	}

	int af;
	unsigned long minmask;
	unsigned long maxmask;
	if (mode == 4) {
		af = AF_INET;
		minmask = 8;
		maxmask = 32;
	} else {
		af = AF_INET6;
		minmask = 32;
		maxmask = 128;
	}

	for (int j = 2; j < argc; j++) {
		unsigned long m;

		char *s = strchr(argv[j], '/');
		if (!s) {
			m = maxmask;
		} else {
			char *t;

			*s = '\0';
			m = strtoul(s + 1, &t, 10);
			if (*t) {
				fputs("invalid mask found in argument '", stderr);
				fputs(argv[j], stderr);
				fputs("', ignoring\n", stderr);
				continue;
			}
			if ((m < minmask) || (m > maxmask)) {
				fputs("mask not in valid range in argument '", stderr);
				fputs(argv[j], stderr);
				fputs("', ignoring\n", stderr);
				continue;
			}
		}
		if (af == AF_INET) {
			struct in_addr ip;
			mode = inet_pton(AF_INET, argv[j], &ip.s_addr);
			write(fd, &ip.s_addr, sizeof(ip.s_addr));
		} else {
			struct in6_addr ip;
			mode = inet_pton(AF_INET6, argv[j], &ip.s6_addr);
			write(fd, &ip.s6_addr, sizeof(ip.s6_addr));
		}
		assert(mode == 1);

		char c = m & 0xff;
		write(fd, &c, 1);
	}
	return close(fd) ? errno : 0;
}
