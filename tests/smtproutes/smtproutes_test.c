#include <control.h>
#include <qdns.h>
#include <qremote/qremote.h>
#include <qremote/starttlsr.h>
#include "test_io/testcase_io.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

const char str_default[] = "default";
const char *clientcertname = str_default;
struct in6_addr outgoingip = IN6ADDR_ANY_INIT;
struct in6_addr outgoingip6 = IN6ADDR_ANY_INIT;

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

void
err_mem(const int doquit)
{
	assert(doquit == 0);
	abort();
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
static struct in6_addr expectedrip;
static struct in6_addr expectedoip = IN6ADDR_ANY_INIT;
static struct in6_addr expectedoip6 = IN6ADDR_ANY_INIT;
static struct ips *mx;
static char *ipexpect, *outipexpect, *outip6expect;
static size_t ipe_len, oipe_len, oip6e_len;
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

	if (!IN6_ARE_ADDR_EQUAL(&outgoingip, &expectedoip)) {
		char gip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &outgoingip, gip, sizeof(gip));
		fprintf(stderr, "expected outgoing ip %s, but got %s\n", outipexpect, gip);
		return 3;
	}

	if (!IN6_ARE_ADDR_EQUAL(&outgoingip6, &expectedoip6)) {
		char gip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &outgoingip6, gip, sizeof(gip));
		fprintf(stderr, "expected outgoing ip6 %s, but got %s\n", outip6expect, gip);
		return 3;
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

	if (!IN6_ARE_ADDR_EQUAL(mx->addr, &expectedrip)) {
		fprintf(stderr, "expected ip %s, but got %s\n", ipexpect, gotip);
		return 3;
	}

	return 0;
}

static int
loadip(const char *fname, char **ipstr, size_t *ilen, struct in6_addr *ipp)
{
	*ilen = loadoneliner(AT_FDCWD, fname, ipstr, 1);

	if (*ilen == (size_t) -1) {
		if (errno != ENOENT) {
			fprintf(stderr, "error %i when opening '%s'\n", errno, fname);
			return EFAULT;
		}
	} else if (*ilen > 0) {
		if (inet_pton(AF_INET6, *ipstr, ipp) != 1) {
			fprintf(stderr, "cannot parse expected IPv6 address %s\n", *ipstr);
			free(*ipstr);
			*ipstr = NULL;
			return EFAULT;
		}
	}

	return 0;
}

int
main(void)
{
	int fd = open("expected_port", O_RDONLY | O_CLOEXEC);
	int r;

	testcase_setup_ask_dnsaaaa(test_ask_dnsaaaa);
	testcase_setup_log_writen(test_log_writen);

	controldir_fd = open("control", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (controldir_fd < 0) {
		fprintf(stderr, "error opening the control dir: %i\n", errno);
		if (fd >= 0)
			close(fd);
		return EFAULT;
	}

	if (loadintfd(fd, &expectedport, 25) != 0) {
		fprintf(stderr, "error loading the expected port");
		return EFAULT;
	}

	r = loadip("expected_ip", &ipexpect, &ipe_len, &expectedrip);
	if (r == 0)
		loadip("expected_outip", &outipexpect, &oipe_len, &expectedoip);
	if (r == 0)
		loadip("expected_outip6", &outip6expect, &oip6e_len, &expectedoip6);
	if (r != 0) {
		free(ipexpect);
		free(outipexpect);
		free(outip6expect);
		return r;
	}

	certlen = loadoneliner(AT_FDCWD, "expected_cert", &certbuf, 1);
	if ((certlen == (size_t) -1) && (errno != ENOENT)) {
		fprintf(stderr, "error %i when opening 'expected_cert'\n", errno);
		free(ipexpect);
		free(outipexpect);
		free(outip6expect);
		return EFAULT;
	}

	mx = smtproute("foo.example.net", strlen("foo.example.net"), &targetport);

	r = verify_route();

	freeips(mx);
	free(ipexpect);
	free(certbuf);
	close(controldir_fd);
	if ((r == 0) && (gotip[0] != '\0')) {
		printf("redirected to IP %s, port %u\n", gotip, targetport);
		if (memcmp(&outgoingip, &in6addr_any, sizeof(in6addr_any)) != 0) {
			char s[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &outgoingip, s, sizeof(s));
			printf("outgoing IPv4: %s\n", s);
		}
		if (memcmp(&outgoingip6, &in6addr_any, sizeof(in6addr_any)) != 0) {
			char s[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &outgoingip6, s, sizeof(s));
			printf("outgoing IPv6: %s\n", s);
		}
	}

	/* free it if it was overwritten in smtproute() */
	free_smtproute_vals();
	free(outipexpect);
	free(outip6expect);

	return r;
}
