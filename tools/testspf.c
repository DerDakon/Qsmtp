#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "qsmtpd.h"
#include "antispam.h"
#include "sstring.h"

struct xmitstat xmitstat;
string heloname = {.s = "caliban.sf-tec.de", .len = 17};

int log_write() {return 0;}
int log_writen() {return 0;}
int dieerror() {return 0;}

extern int spf_makro(char *token, const char *domain, int ex, char **result);

int
main(int argc, char *argv[])
{
	char *tst;
	int i;
	char *arg;

	xmitstat.mailfrom.s = getenv("SENDER");
	if (!xmitstat.mailfrom.s)
		xmitstat.mailfrom.s = "strong-bad@email.example.com";
	xmitstat.mailfrom.len = strlen(xmitstat.mailfrom.s);
	xmitstat.remoteip = "5f05:2000:80ad:5800::1";
	xmitstat.remotehost.s = "mx.example.org";
	xmitstat.remotehost.len = 14;
	
	if (argc > 1) {
		if (strcmp(argv[1], "-4")) {
			arg = argv[1];
		} else {
			if (argc > 2) {
				arg = argv[2];
				xmitstat.remoteip = "::ffff:192.0.2.3";
			} else {
				arg = "%{i}";
			}
		}
	} else {
		arg = "%{s}";
	}
	inet_pton(AF_INET6, xmitstat.remoteip, &xmitstat.sremoteip);
	i = spf_makro(arg, "email.example.com", 0, &tst);

	if (!i)
		puts(tst);
	return i;
}
