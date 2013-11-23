#include "control.h"
#include "qdns.h"
#include "qremote.h"
#include "test_io/testcase_io.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
test_log_writen(int priority __attribute__((unused)), const char **msg)
{
	int i;

	printf("LOG: ");
	for (i = 0; msg[i] != NULL; i++)
		printf("%s", msg[i]);
	printf("\n");
}

void
err_confn(const char **msg, void *freebuf)
{
	test_log_writen(0, msg);
	free(freebuf);

	exit(1);
}


int
test_ask_dnsaaaa(const char *domain, struct ips **ips)
{
	const char *ipv6;

	if (strcmp(domain, "mail.example.net") == 0) {
		ipv6 = "dead:cafe:beef:babe::1";
	} else {
		*ips = NULL;
		errno = ENOENT;
		return -1;
	}

	*ips = malloc(sizeof(**ips));

	if (*ips == NULL)
		return -1;

	memset(*ips, 0, sizeof(**ips));

	if (inet_pton(AF_INET6, ipv6, &(*ips)->addr) != 1) {
		fprintf(stderr, "cannot parse example IPv6 address\n");
		exit(EFAULT);
	}

	return 0;
}

int main(void)
{
	struct ips *mx;
	unsigned int targetport = 0;
	unsigned long expectedport;
	int fd = open("expected_port", O_RDONLY);
	char *ipexpect;
	size_t ipe_len;
	struct in6_addr expectedip;
	char gotip[INET6_ADDRSTRLEN];

	testcase_setup_ask_dnsaaaa(test_ask_dnsaaaa);
	testcase_setup_log_writen(test_log_writen);

	if (loadintfd(fd, &expectedport, 25) != 0) {
		fprintf(stderr, "error loading the expected port");
		return EFAULT;
	}

	ipe_len = loadoneliner("expected_ip", &ipexpect, 1);

	if (ipe_len == (size_t) -1) {
		if (errno != ENOENT) {
			fprintf(stderr, "error %i when opening 'expected_ip'\n", errno);
			exit(EFAULT);
		}
	} else if (ipe_len > 0) {
		if (inet_pton(AF_INET6, ipexpect, &expectedip) != 1) {
			fprintf(stderr, "cannot parse expected IPv6 address %s\n", ipexpect);
			free(ipexpect);
			exit(EFAULT);
		}
	}

	mx = smtproute("foo.example.net", strlen("foo.example.net"), &targetport);

	if (targetport != expectedport) {
		fprintf(stderr, "expected port %lu, but got port %u\n", expectedport, targetport);
		freeips(mx);
		return 1;
	}

	if (mx == NULL) {
		if (ipe_len == (size_t) -1)
			return 0;

		fprintf(stderr, "no matching entry found for foo.example.net\n");
		return 1;
	}

	if (mx->next != NULL) {
		fprintf(stderr, "only one IP expected as result\n");
		freeips(mx);
		return 2;
	}

	inet_ntop(AF_INET6, &mx->addr, gotip, sizeof(gotip));

	if (memcmp(&(mx->addr), &expectedip, sizeof(expectedip)) != 0) {
		fprintf(stderr, "expected ip %s, but got %s\n", ipexpect, gotip);
		freeips(mx);
		free(ipexpect);
		return 3;
	}

	freeips(mx);
	free(ipexpect);
	printf("redirected to IP %s, port %u\n", gotip, targetport);

	return 0;
}
