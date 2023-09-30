/** \file testspf.c
 \brief tool for checking SPF entries

 \details With this tool you can check a given SPF string, passed as argument to the binary,
 with a few hardcoded values. No network looksups will be done. This is mainly useful when
 debugging the SPF implementation. See spfquery for a tool to do actual SPF lookups.
 */

#include <qsmtpd/antispam.h>
#include <qsmtpd/qsmtpd.h>
#include <sstring.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>

#include <string.h>

struct xmitstat xmitstat;
string heloname = {.s = "caliban.sf-tec.de", .len = 17};

int log_write() {return 0;}
int log_writen() {return 0;}
int dieerror() {return 0;}
int socketd;

extern int spf_makro(const char *token, const char *domain, int ex, char **result);

int
main(int argc, char *argv[])
{
	char *arg;

	xmitstat.mailfrom.s = getenv("SENDER");
	if (!xmitstat.mailfrom.s)
		xmitstat.mailfrom.s = "strong-bad@email.example.com";
	xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);
	memcpy(xmitstat.remoteip, "5f05:2000:80ad:5800::1", 23);
	xmitstat.remotehost.s = "mx.example.org";
	xmitstat.remotehost.len = 14;

	if (argc > 1) {
		if (strcmp(argv[1], "-4")) {
			arg = argv[1];
		} else {
			if (argc > 2) {
				arg = argv[2];
				memcpy(xmitstat.remoteip, "::ffff:192.0.2.3", 17);
			} else {
				arg = "%{i}";
			}
		}
	} else {
		arg = "%{s}";
	}
	inet_pton(AF_INET6, xmitstat.remoteip, &xmitstat.sremoteip);
	char *tst;
	int i = spf_makro(arg, "email.example.com", 0, &tst);

	if (!i)
		puts(tst);
	return i;
}
