#include <control.h>
#include <qdns.h>
#include <qremote/qremote.h>
#include <qremote/starttlsr.h>
#include "test_io/testcase_io.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *clientcertname = "default";

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
test_ask_dnsaaaa(const char *domain, struct in6_addr **ips)
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

	if (inet_pton(AF_INET6, ipv6, *ips) != 1) {
		fprintf(stderr, "cannot parse example IPv6 address\n");
		exit(EFAULT);
	}

	return 1;
}

static unsigned int targetport = 0;
static unsigned long expectedport;
static struct in6_addr expectedip;
static struct ips *mx;
static char *ipexpect;
static size_t ipe_len;
static char *certbuf;
static size_t certlen;
static char gotip[INET6_ADDRSTRLEN];

static int
verify_route(void)
{
	char *expected_cert = (char *)"default";

	if (certbuf != NULL)
		expected_cert = certbuf;

	if (targetport != expectedport) {
		fprintf(stderr, "expected port %lu, but got port %u\n", expectedport, targetport);
		return 1;
	}

	if (strcmp(expected_cert, clientcertname) != 0) {
		fprintf(stderr, "expected cert name %s, but got %s\n", expected_cert, clientcertname);
		return 4;
	}

	if (mx == NULL) {
		if (ipe_len == (size_t) -1)
			return 0;

		fprintf(stderr, "no matching entry found for foo.example.net\n");
		return 1;
	}

	if (mx->next != NULL) {
		fprintf(stderr, "only one IP expected as result\n");
		return 2;
	}

	inet_ntop(AF_INET6, mx->addr, gotip, sizeof(gotip));

	if (!IN6_ARE_ADDR_EQUAL(mx->addr, &expectedip)) {
		fprintf(stderr, "expected ip %s, but got %s\n", ipexpect, gotip);
		return 3;
	}

	return 0;
}

int main(void)
{
	int fd = open("expected_port", O_RDONLY | O_CLOEXEC);
	int r;

	testcase_setup_ask_dnsaaaa(test_ask_dnsaaaa);
	testcase_setup_log_writen(test_log_writen);

	controldir_fd = open("control", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (loadintfd(fd, &expectedport, 25) != 0) {
		fprintf(stderr, "error loading the expected port");
		return EFAULT;
	}

	ipe_len = loadoneliner(AT_FDCWD, "expected_ip", &ipexpect, 1);

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

	certlen = loadoneliner(AT_FDCWD, "expected_cert", &certbuf, 1);
	if ((certlen == (size_t) -1) && (errno != ENOENT)) {
		fprintf(stderr, "error %i when opening 'expected_cert'\n", errno);
		free(ipexpect);
		exit(EFAULT);
	}

	mx = smtproute("foo.example.net", strlen("foo.example.net"), &targetport);

	r = verify_route();

	freeips(mx);
	free(ipexpect);
	free(certbuf);
	close(controldir_fd);
	if ((r == 0) && (gotip[0] != '\0'))
		printf("redirected to IP %s, port %u\n", gotip, targetport);

	return r;
}
