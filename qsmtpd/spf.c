#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "qsmtpd.h"
#include "antispam.h"
#include "sstring.h"
#include "dns.h"

#define WSPACE(x) (((x) == ' ') || ((x) == '\t') || ((x) == '\r') || ((x) == '\n'))

int spfmx(struct ips *, char *);
int spfa(const char *);
int spfip4(char *);
int spfip6(char *);
int spflookup(const char *, const int);

/**
 * check_host - look up SPF records for domain
 *
 * @domain: no idea what this might be for
 *
 * returns: one of the SPF_* constants defined in include/antispam.h
 *
 * This works a like the check_host in the SPF draft but takes two arguments less. The remote ip and the full
 * sender address can be taken directly from xmitstat.
 */
int
check_host(const char *domain)
{
	if (!strcmp("unknown", xmitstat.remoteip))
		return SPF_TEMP_ERROR;

	return spflookup(domain, 0);
}

/**
 * spflookup - look up SPF records for domain
 *
 * @domain: no idea what this might be for
 * @rec: recursion level
 *
 * returns: one of the SPF_* constants defined in include/antispam.h or -1 on ENOMEM
 */
int
spflookup(const char *domain, const int rec)
{
	char *txt, *token, *valid = NULL, *redirect = NULL;
	int i, result = SPF_NONE, prefix;

	if (rec >= 20)
		return SPF_HARD_ERROR;

	if (domainvalid(domain, 0))
		return SPF_FAIL_MALF;

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
	token = txt;
	while ((token = strstr(token, "v=spf1"))) {
		if (valid) {
			free(txt);
			return SPF_HARD_ERROR;
		} else {
			token += 6;
			valid = token;
		}
	}
	if (!valid) {
		free(txt);
		return SPF_NONE;
	}
	token = valid;
	while (*token && (result != SPF_PASS)) {
#warning FIXME: add SPF parsing here
		while (WSPACE(*token)) {
			token++;
		}
		if (!*token)
			break;
		switch(*token) {
			case '-':	token++; prefix = SPF_FAIL_PERM; break;
			case '~':	token++; prefix = SPF_SOFTFAIL; break;
			case '+':	token++; prefix = SPF_PASS; break;
			case '?':	token++; prefix = SPF_NEUTRAL; break;
			default:	if (((*token >= 'a') && (*token <= 'z')) || ((*token >= 'A') && (*token <= 'Z'))) {
						prefix = SPF_PASS;
					} else {
						free(txt);
						return SPF_HARD_ERROR;
					}
		}
		if (!strncasecmp(token, "mx", 2) && (WSPACE(*(token + 2)) || !*(token + 2) || (*(token + 2) == ':'))) {
			token += 2;
			if (rec || (*token == ':') || !xmitstat.mailfrom.len) {
				struct ips* mx;
				int k;
				char *c = NULL;

				if (*token == ':') {
					char oldc, *c;

					c = ++token;
					while (*c && !WSPACE(*c) && (*c != '/')) {
						c++;
					}
					oldc = *c;
					*c = '\0';
					k = ask_dnsmx(token, &mx);
					*c = oldc;
					if (oldc != '/') {
						c = NULL;
					}
				} else {
					k = ask_dnsmx(domain, &mx);
				}
				if (k < 0) {
					prefix = SPF_TEMP_ERROR;
					result = SPF_PASS;
				} else {
					result = spfmx(mx, c);
					freeips(mx);
				}
			} else {
				switch (xmitstat.fromdomain) {
					case 0:	result = spfmx(xmitstat.frommx, NULL);
						break;
					case 1:	prefix = SPF_FAIL_NONEX;
						result = SPF_PASS;
						break;
					case 2:	prefix = SPF_TEMP_ERROR;
						result = SPF_PASS;
						break;
					case 3:	prefix = SPF_HARD_ERROR;
						result = SPF_PASS;
						break;
				}
			}
		} else if (!strncasecmp(token, "all", 3) && (WSPACE(*(token + 3)) || !*(token + 3))) {
			result = SPF_PASS;
		} else if (((*token == 'a') || (*token == 'A')) &&
					(WSPACE(*(token + 1)) || !*(token + 1) || (*(token + 1) == ':'))) {
			token++;
			if (*token == ':') {
				char *c = token, oldc;

				do {
					c++;
				} while (*c && !WSPACE(*c));
				oldc = *c;
				*c = '\0';
				result = spfa(token + 1);
				*c = oldc;
				token = c;
			} else {
				result = spfa(domain);
			}
		} else if (!strncasecmp(token, "ip4:", 4)) {
			token += 4;
			result = spfip4(token);
		} else if (!strncasecmp(token, "ip6:", 4)) {
			token += 4;
			result = spfip6(token);
		} else if (!strncasecmp(token, "include:", 8)) {
			char *n;
			int flagnext = 0;

			token += 8;
			n = token;
			while (!WSPACE(*n) && *n) {
				n++;
			}
			if (*n) {
				*n = '\0';
				flagnext = 1;
			}
			result = spflookup(token, rec + 1);
			switch (result) {
				case SPF_NONE:	result = SPF_PASS;
						prefix = SPF_FAIL_NONEX;
						break;
				case SPF_TEMP_ERROR:
				case SPF_HARD_ERROR:
				case SPF_PASS:	prefix = result;
						result = SPF_PASS;
						break;
				case -1:	break;
				default:	result = SPF_NONE;
			}
			token = n + flagnext;
		} else if (!strncasecmp(token, "redirect=", 9)) {
			token += 9;
			if (!redirect) {
				redirect = token;
			}
		} else {
			result = 0;
		}
/* skip to the end of this token */
		while (*token && !WSPACE(*token)) {
			token++;
		}
		if ((result == SPF_TEMP_ERROR) || (result == SPF_HARD_ERROR)) {
			prefix = result;
			result = SPF_PASS;
		}
	}
	free(txt);
	if (result < 0)
		return result;
	if (result == SPF_PASS)
		return prefix;
	if (redirect) {
		char *e = redirect;

		while (*e && !WSPACE(*e)) {
			e++;
		}
		*e = '\0';
		return spflookup(redirect, rec + 1);
	}
	return SPF_NEUTRAL;
}

#define WRITE(fd, s, l) if ( (rc = write((fd), (s), (l))) < 0 ) return rc

int
spfreceived(const int fd, const int spf) {
	int rc;
	char *fromdomain;

	if (xmitstat.mailfrom.len) {
		fromdomain = strchr(xmitstat.mailfrom.s, '@') + 1;
	} else {
		fromdomain = xmitstat.helostr.s;
	}
	WRITE(fd, "Received-SPF: ", 14);
	WRITE(fd, heloname, strlen(heloname));
	if (spf == SPF_HARD_ERROR) {
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
			case SPF_FAIL_NONEX:
			case SPF_FAIL_MALF:
			case SPF_FAIL_PERM:	WRITE(fd, "fail", 4); break;
		}
	}
	WRITE(fd, "\n", 1);
	return 0;
}

/* the SPF routines
 *
 * return values:
 *  SPF_NONE: no match
 *  SPF_PASS: match
 *  SPF_HARD_ERROR: parse error
 * -1: error (ENOMEM)
 */
int
spfmx(struct ips *mx, char *cidr)
{
	unsigned long ip6l = 128, ip4l = 32;
/* Don't use the implicit MX for this. There are either all MX records
 * implicit or none so we only have to look at the first one */
	if (!mx) {
		return SPF_NONE;
	}
	if (mx->priority >= 65536) {
		return SPF_NONE;
	}
	if (cidr) {
		char *n;

		ip4l = strtoul(cidr + 1, &n, 10);
		if ((ip4l < 8) || (ip4l > 32) || (*n && !WSPACE(*n) && (*n != '/'))) {
			return SPF_HARD_ERROR;
		}
		if (*n == '/') {
			if (*(n + 1) != '/')
				return SPF_HARD_ERROR;
			ip6l = strtoul(n + 2, &n, 10);
			if ((ip4l < 8) || (ip4l > 128) || (*n && !WSPACE(*n))) {
				return SPF_HARD_ERROR;
			}
		}
	}
	if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
		while (mx) {
			if (ip4_matchnet(&xmitstat.sremoteip, (struct in_addr *) &(mx->addr.s6_addr32[3]), ip4l))
				return SPF_PASS;
			mx = mx->next;
		}
	} else {
		while (mx) {
			if (ip6_matchnet(&xmitstat.sremoteip, &mx->addr, ip6l))
				return SPF_PASS;
			mx = mx->next;
		}
	}
	return SPF_NONE;
}

#warning FIXME: add cidr-length check to spfa
int
spfa(const char *domain)
{
	struct ips *ip, *thisip;
	int r = 0;

	switch (ask_dnsa(domain, &ip)) {
		case 0:	thisip = ip;
			r = SPF_NONE;
			while (thisip) {
				if (IN6_ARE_ADDR_EQUAL(&(thisip->addr), &(xmitstat.sremoteip))) {
					r = SPF_PASS;
					break;
				}
				thisip = thisip->next;
			}
			freeips(ip);
			break;
		case 1:	r = SPF_NONE;
			break;
		case 2:	r = SPF_TEMP_ERROR;
			break;
		case -1:	r = -1;
			break;
		default:r = SPF_HARD_ERROR;
	}
	return r;
}

int
spfip4(char *domain)
{
	char *sl = domain;
	char osl;	/* char at *sl before we overwrite it */
	struct in_addr net;
	unsigned long u;

	if (!IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip))
		return SPF_NONE;
	while (((*sl >= '0') && (*sl <= '9')) || (*sl == '.')) {
		sl++;
	}
	if (*sl == '/') {
		osl = *sl;
		*sl = '\0';
		u = strtoul(sl + 1, &sl, 10);
		if ((u < 8) || (u > 32) || !WSPACE(*sl))
			return SPF_HARD_ERROR;
	} else if (WSPACE(*sl) || !*sl) {
		osl = *sl;
		*sl = '\0';
		u = 32;
	} else {
		return SPF_HARD_ERROR;
	}
	if (!inet_pton(AF_INET, domain, &net))
		return SPF_HARD_ERROR;
	*sl = osl;
	return ip4_matchnet(&xmitstat.sremoteip, &net, u) ? SPF_PASS : SPF_NONE;
}

int
spfip6(char *domain)
{
	char *sl = domain;
	char osl;	/* char at *sl before we overwrite it */
	struct in6_addr net;
	unsigned long u;

	if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip))
		return SPF_NONE;
	while (((*sl >= '0') && (*sl <= '9')) || ((*sl >= 'a') && (*sl <= 'f')) || ((*sl >= 'A') && (*sl <= 'F')) ||
					(*sl == ':') || (*sl == '.')) {
		sl++;
	}
	if (*sl == '/') {
		osl = *sl;
		*sl = '\0';
		u = strtoul(sl + 1, &sl, 10);
		if ((u < 8) || (u > 128) || !WSPACE(*sl))
			return SPF_HARD_ERROR;
	} else if (WSPACE(*sl) || !*sl) {
		osl = *sl;
		*sl = '\0';
		u = 128;
	} else {
		return SPF_HARD_ERROR;
	}
	osl = *sl;
	*sl = '\0';
	if (!inet_pton(AF_INET6, domain, &net))
		return SPF_HARD_ERROR;
	*sl = osl;
	return ip6_matchnet(&xmitstat.sremoteip, &net, (unsigned char) (u & 0xff)) ? SPF_PASS : SPF_NONE;
}
