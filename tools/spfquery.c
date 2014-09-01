/** \file testspf.c
 \brief tool for checking SPF entries
 */

#include <qsmtpd/antispam.h>
#include <qsmtpd/qsmtpd.h>
#include <sstring.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct xmitstat xmitstat;
string heloname = {.s = "caliban.sf-tec.de", .len = 17};

int log_write() {return 0;}
int log_writen() {return 0;}
int dieerror() {return 0;}
int socketd;

extern int spf_makro(char *token, const char *domain, int ex, char **result);

int
main(int argc, char *argv[])
{
	int i;
	const char *s;

	xmitstat.mailfrom.s = getenv("SENDER");
	if (!xmitstat.mailfrom.s) {
		xmitstat.mailfrom.s = "strong-bad@email.example.com";
		s = strchr(xmitstat.mailfrom.s, '@');
	} else {
		s = strchr(xmitstat.mailfrom.s, '@');
		if (s == NULL) {
			fprintf(stderr, "SENDER contains no @\n");
			return EINVAL;
		}
		s++;
	}
	xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);
	xmitstat.remotehost.s = "mx.example.org";
	xmitstat.remotehost.len = 14;

	if (argc > 1) {
		if (strcmp(argv[1], "-4") == 0) {
			if (argc > 2) {
				i = inet_pton(AF_INET, argv[2], xmitstat.sremoteip.s6_addr32 + 3);
				if (i <= 0) {
					fprintf(stderr, "failed to parse '%s' as IPv4 address\n", argv[2]);
					return EINVAL;
				}
			} else {
				fprintf(stderr, "argument '-4' given but no IP address\n");
				return EINVAL;
			}
			xmitstat.sremoteip.s6_addr32[0] = htonl(0);
			xmitstat.sremoteip.s6_addr32[1] = htonl(0);
			xmitstat.sremoteip.s6_addr32[2] = htonl(0xffff);
		} else if (strcmp(argv[1], "-6") == 0) {
			if (argc > 2) {
				i = inet_pton(AF_INET6, argv[2], &xmitstat.sremoteip);
				if (i <= 0) {
					fprintf(stderr, "failed to parse '%s' as IPv6 address\n", argv[2]);
					return EINVAL;
				}
			} else {
				fprintf(stderr, "argument '-6' given but no IP address\n");
				return EINVAL;
			}
		} else {
			fprintf(stderr, "unknown argument '%s'\n", argv[1]);
			return EINVAL;
		}
		inet_ntop(AF_INET6, &xmitstat.sremoteip, xmitstat.remoteip, sizeof(xmitstat.remoteip));
	} else {
		strcpy(xmitstat.remoteip, "5f05:2000:80ad:5800::1");
		inet_pton(AF_INET6, xmitstat.remoteip, &xmitstat.remoteip);
	}
	inet_pton(AF_INET6, xmitstat.remoteip, &xmitstat.sremoteip);

	i = check_host(s);

	return i;
}
