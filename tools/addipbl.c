#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int
main(int argc, char *argv[])
{
	int fd, j;

	if (argc == 1) {
		fputs("Usage: ", stdout);
		fputs(argv[0], stdout);
		fputs(" file ip [ip ...]\n", stdout);
		return 1;
	}
	fd = open(argv[1], O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1)
		return errno;
	for (j = 2; j < argc; j++) {
		char *s, *t, c;
		unsigned long m;
		struct in_addr ip;

		s = strchr(argv[j], '/');
		if (!s) {
			fputs("no / found in argument '", stderr);
			fputs(argv[j], stderr);
			fputs("'\n", stderr);
			continue;
		}
		*s = '\0';
		m = strtoul(s + 1, &t, 10);
		if (*t) {
			fputs("invalid mask found in argument '", stderr);
			fputs(argv[j], stderr);
			fputs("'\n", stderr);
			continue;
		}
		if ((m < 8) || (m > 32)) {
			fputs("mask not in range 8..32 in argument '", stderr);
			fputs(argv[j], stderr);
			fputs("'\n", stderr);
			continue;
		}
		if (inet_pton(AF_INET, argv[j], &ip) <= 0) {
			fputs("invalid IP address in argument '", stderr);
			fputs(argv[j], stderr);
			fputs("'\n", stderr);
			continue;
		}
		write(fd, &ip.s_addr, 4);
		c = m & 0xff;
		write(fd, &c, 1);
	}
	return close(fd) ? errno : 0;
}
