#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include "qsmtpd.h"
#include "antispam.h"
#include "sstring.h"
#include "dns.h"

/**
 * spflookup - look up SPF records for domain
 *
 * @domain: no idea what this might be for
 *
 * returns: one of the SPF_* constants defined in include/antispam.h
 */
int
spflookup(const char *domain, const int rec)
{
	char *txt;
	int i;

	return SPF_NONE;
	if (rec >= 20)
		return SPF_LOOP;

	if (!strcmp("unknown", xmitstat.remoteip))
		return SPF_UNKNOWN;

	i = dnstxt(&txt, domain);
	if (i) {
		switch (errno) {
			case EIO:
			case ECONNREFUSED:
			case EAGAIN:	return SPF_TEMP_ERROR;
			case EINVAL:	return SPF_HARD_ERROR;
			case ENOMEM:
			default:	return -1;
		}
	}
	if (!txt)
		return SPF_NONE;
#warning FIXME: add SPF parsing here
	if (!strncmp("v=spf1 ", txt, 7)) {
		free(txt);
		return SPF_NONE;
	}
	free(txt);
	return SPF_NEUTRAL;
}

#define WRITE(fd, s, l) if ( (rc = write((fd), (s), (l))) < 0 ) return rc

int
spfreceived(const int fd, const int spf) {
	int rc;
	char *fromdomain = strchr(xmitstat.mailfrom.s, '@') + 1;

	WRITE(fd, "Received-SPF: ", 14);
	WRITE(fd, heloname, strlen(heloname));
	if ((spf == SPF_HARD_ERROR) || (spf == SPF_LOOP)) {
		WRITE(fd, ": syntax error while parsing SPF entry for", 42);
		WRITE(fd, fromdomain, strlen(fromdomain));
	} else if (spf == SPF_TEMP_ERROR) {
		WRITE(fd, ": can't get SPF entry for ", 26);
		WRITE(fd, fromdomain, strlen(fromdomain));
		WRITE(fd, " (DNS problem)", 14);
	} else if (spf == SPF_NONE) {
		WRITE(fd, ": no SPF entry for ", 19);
		WRITE(fd, fromdomain, strlen(fromdomain));
	} else if (spf == SPF_UNKNOWN) {
		WRITE(fd, ": can not figure out SPF status for ", 36);
		WRITE(fd, fromdomain, strlen(fromdomain));
	} else {
		WRITE(fd, ": SPF status for ", 17);
		WRITE(fd, fromdomain, strlen(fromdomain));
		WRITE(fd, " is ", 4);
		switch(spf) {
			case SPF_PASS:		WRITE(fd, "pass", 4); break;
			case SPF_SOFTFAIL:	WRITE(fd, "softfail", 8); break;
			case SPF_NEUTRAL:	WRITE(fd, "neutral", 7); break;
			case SPF_FAIL:		WRITE(fd, "fail", 4); break;
		}
	}
	WRITE(fd, "\n", 1);
	return 0;
}
