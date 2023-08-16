/** \file dumpipbl.c
 \brief helper program dump the list of Qsmtp's IP filters
 */

#include <mmap.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <unistd.h>

static void err_usage(const char *arg) __attribute__ ((noreturn));

static void
err_usage(const char *arg)
{
	fputs("Usage: ", stdout);
	fputs(arg, stdout);
	fputs("[-4|-6] file\n", stdout);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int mode;	/* IPv4 vs. IPv6 addresses */
	int filearg = 1;

	if (argc == 1 || argc > 3) {
		err_usage(argv[0]);
	}

	if (strcmp(argv[1], "-4") == 0) {
		mode = 4;
		filearg = 2;
	} else if (strcmp(argv[1], "-6") == 0) {
		mode = 6;
		filearg = 2;
	} else {
		err_usage(argv[0]);
	}

	int fd;
	off_t len;
	const unsigned char *ips = mmap_name(AT_FDCWD, argv[filearg], &len, &fd);
	if (ips == NULL)
		return errno;

	int af;
	size_t struct_size;
	if (mode == 4) {
		af = AF_INET;
		struct_size = sizeof(struct in_addr);
	} else {
		af = AF_INET6;
		struct_size = sizeof(struct in6_addr);
	}
	const size_t record_size = struct_size + 1;

	if (len % record_size != 0) {
		fputs("file size not multiple of struct size\n", stderr);
		flock(fd, LOCK_UN);
		return 1;
	}

	const unsigned char *pos = ips;
	char outbuf[INET6_ADDRSTRLEN];
	while (pos < ips + len) {
		struct in6_addr ip;
		memcpy(&ip, pos, struct_size);
		inet_ntop(af, pos, outbuf, sizeof(outbuf));
		pos += struct_size;
		printf("%s/%u\n", outbuf, (unsigned int)*pos);
		pos++;
	}

	return flock(fd, LOCK_UN) ? errno : 0;
}
