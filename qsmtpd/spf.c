#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "qsmtpd.h"
#include "antispam.h"
#include "sstring.h"
#include "dns.h"

#define WSPACE(x) (((x) == ' ') || ((x) == '\t') || ((x) == '\r') || ((x) == '\n'))

int spfmx(const char *, char *);
int spfa(const char *, char *);
int spfip4(char *);
int spfip6(char *);
int spflookup(const char *, const int);
int spfptr(const char *, char *);
int spfexists(char *);
int spf_domainspec(char *token, char **domain, int *ip4cidr, int *ip6cidr);

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
		if (!strncasecmp(token, "mx", 2) &&
				(WSPACE(*(token + 2)) || !*(token + 2) || (*(token + 2) == ':') || (*(token + 2) == '/'))) {
			token += 2;
			result = spfmx(domain, token);
		} else if (!strncasecmp(token, "ptr", 3) &&
				(WSPACE(*(token + 2)) || !*(token + 2) || (*(token + 2) == ':'))) {
			token += 3;
			result = spfptr(domain, token);
		} else if (!strncasecmp(token, "exists:", 7)) {
			token += 7;
			result = spfexists(token);
		} else if (!strncasecmp(token, "all", 3) && (WSPACE(*(token + 3)) || !*(token + 3))) {
			result = SPF_PASS;
		} else if (((*token == 'a') || (*token == 'A')) &&
					(WSPACE(*(token + 1)) || !*(token + 1) || (*(token + 1) == ':'))) {
			token++;
			result = spfa(domain, token);
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
	if (result == SPF_PASS) {
		if (SPF_FAIL(prefix)) {
			char *ex;

#warning FIXME: this must be case invalid
			if ((ex = strstr(txt, "exp="))) {
				int ip4, ip6, i;
				if ((i = spf_domainspec(ex, &xmitstat.spfexp, &ip4, &ip6))) {
					xmitstat.spfexp = NULL;
				}
			}
		}
		return prefix;
	}
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
	WRITE(fd, heloname.s, heloname.len);
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
spfmx(const char *domain, char *token)
{
	int ip6l, ip4l, i;
	struct ips *mx;
	char *domainspec;

	if ( (i = spf_domainspec(token, &domainspec, &ip4l, &ip6l)) ) {
		return i;
	}
	if (ip4l < 0) {
		ip4l = 32;
	}
	if (ip6l < 0) {
		ip6l = 128;
	}
	if (domainspec) {
		i = ask_dnsmx(domainspec, &mx);
		free(domainspec);
	} else {
		i = ask_dnsmx(domain, &mx);
	}
	switch (i) {
		case 1: return SPF_NONE;
		case 2: return SPF_TEMP_ERROR;
		case 3:	return SPF_HARD_ERROR;
		case -1:return -1;
	}
	if (!mx) {
		return SPF_NONE;
	}
/* Don't use the implicit MX for this. There are either all MX records
 * implicit or none so we only have to look at the first one */
	if (mx->priority >= 65536) {
		return SPF_NONE;
	}
	if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
		while (mx) {
			if (IN6_IS_ADDR_V4MAPPED(&(mx->addr)) &&
					ip4_matchnet(&xmitstat.sremoteip, (struct in_addr *) &(mx->addr.s6_addr32[3]), ip4l))
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

int
spfa(const char *domain, char *token)
{
	int ip6l, ip4l, i, r = 0;
	struct ips *ip, *thisip;
	char *domainspec;

	if ( (i = spf_domainspec(token, &domainspec, &ip4l, &ip6l)) ) {
		return i;
	}
	if (ip4l < 0) {
		ip4l = 32;
	}
	if (ip6l < 0) {
		ip6l = 128;
	}
	if (domainspec) {
		i = ask_dnsa(domainspec, &ip);
		free(domainspec);
	} else {
		i = ask_dnsa(domain, &ip);
	}

	switch (i) {
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
spfexists(char *token)
{
	int ip6l, ip4l, i, r = 0;
	struct ips *ip, *thisip;
	char *domainspec;

	if ( (i = spf_domainspec(token, &domainspec, &ip4l, &ip6l)) ) {
		return i;
	}
	if ((ip4l > 0) || (ip6l > 0) || !domainspec) {
		return SPF_HARD_ERROR;
	}
	i = ask_dnsa(domainspec, &ip);
	free(domainspec);

	switch (i) {
		case 0:	thisip = ip;
			r = SPF_NONE;
			while (thisip) {
				if (IN6_IS_ADDR_V4MAPPED(&thisip->addr) && 
						IN6_ARE_ADDR_EQUAL(&thisip->addr, &xmitstat.sremoteip)) {
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
spfptr(const char *domain, char *token)
{
	int ip6l, ip4l, i, r = 0;
	struct ips *ip, *thisip;
	char *domainspec;

	if (!xmitstat.remotehost.len) {
		return SPF_NONE;
	}
	if ( (i = spf_domainspec(token, &domainspec, &ip4l, &ip6l)) ) {
		return i;
	}
	if ((ip4l > 0) || (ip6l > 0)) {
		free(domainspec);
		return SPF_HARD_ERROR;
	}
	if (domainspec) {
		i = ask_dnsa(domainspec, &ip);
		free(domainspec);
	} else {
		i = ask_dnsa(domain, &ip);
	}

	switch (i) {
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

#define APPEND(addlen, addstr) \
	{\
		char *r2;\
		unsigned int oldl = l;\
		\
		l += addlen;\
		r2 = realloc(res, l);\
		if (!r2) { free(res); return -1;}\
		memcpy(res + oldl, addstr, addlen);\
	}
#define PARSEERR	{free(res); return SPF_HARD_ERROR;}

/**
 * spf_makro - expand a SPF makro
 *
 * @token: the token to parse
 * @domain: the current domain string
 * @exp: if this is an exp string
 * @result: the resulting string is stored here
 *
 * returns: 0 on success, -1 on ENOMEM, SPF_{HARD,TEMP}_ERROR on problems
 */
int
spf_makro(char *token, const char *domain, int exp, char **result)
{
	char *res;
	char *p;

	if (!(p = strchr(token, '%'))) {
		res = malloc(strlen(token));
		if (!res) {
			return -1;
		}
		memcpy(res, token, strlen(token));
	} else {
		unsigned int l = p - token;

		res = malloc(l);
		if (!res) {
			return -1;
		}
		memcpy(res, token, l);
		do {
			char *oldp;

			switch (*++p) {
				case '-':	APPEND(3, "%20");
						p++;
						break;
				case '_':	APPEND(1, " ");
						p++;
						break;
				case '%':	APPEND(1, "%");
						p++;
						break;
				case '{':	switch (*++p) {
							case 's':	if (*++p != '}') {
										PARSEERR;
									}
									if (xmitstat.mailfrom.len) {
										APPEND(xmitstat.mailfrom.len,
												xmitstat.mailfrom.s);
									} else {
									}
									p++;
									break;
							case 'l':	if (*++p != '}') {
										PARSEERR;
									}
									if (xmitstat.mailfrom.len) {
										char *at = strchr(xmitstat.mailfrom.s, '@');
	
										APPEND(at - xmitstat.mailfrom.s,
												xmitstat.mailfrom.s);
									} else {
										APPEND(10, "postmaster");
									}
									p++;
									break;
							case 'o':	if (*++p != '}') {
										PARSEERR;
									}
									if (xmitstat.mailfrom.len) {
										char *at = strchr(xmitstat.mailfrom.s, '@');
										unsigned int offset =
												at - xmitstat.mailfrom.s + 1;
	
										APPEND(xmitstat.mailfrom.len - offset,
												at + 1);
									} else {
										APPEND(xmitstat.helostr.len,
												xmitstat.helostr.s);
									}
									p++;
									break;
							case 'd':	switch (*++p) {
										case '}':	APPEND(strlen(domain), domain);
												break;
										default:	PARSEERR;
									}
									break;
							case 'c':
							case 'i':	if ((*p == 'c') && !exp) {
										PARSEERR;
									}
									if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
										char *r;

										r = realloc(res, l + INET_ADDRSTRLEN);
										if (!r) {
											free(res);
											return -1;
										}
										if (*++p == 'r') {
											if (*++p != '}') {
												PARSEERR;
											}
											l += reverseip4(res + l);
										} else if (*p == '}') {
											inet_ntop(AF_INET,
												&(xmitstat.sremoteip.s6_addr32[3]),
												res, INET_ADDRSTRLEN);
											l += reverseip4(res + l);
										} else {
											PARSEERR;
										}
									} else {
									}
							case 't':	if (!exp) {
										PARSEERR;
									}
							case 'p':	if (*++p != '}') {
										PARSEERR;
									}
									p++;
									if (xmitstat.remotehost.len) {
										APPEND(xmitstat.remotehost.len,
												xmitstat.remotehost.s);
									} else {
										APPEND(7, "unknown");
									}
									break;
							case 'r':	if (!exp) {
										PARSEERR;
									}
									if (*++p != '}') {
										PARSEERR;
									}
									p++;
									APPEND(heloname.len, heloname.s);
									break;
							case 'v':	if (*++p != '}') {
										PARSEERR;
									}
									p++;
									if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
										APPEND(7, "in-addr");
									} else {
										APPEND(3, "ip6");
									}
									break;
							case 'h':	if (*++p != '}') {
										PARSEERR;
									}
									p++;
									APPEND(10,"deprecated");
									break;
							default:	APPEND(7,"unknown");
						}
						break;
				default:	APPEND(1, "%");
						/* no p++ here! */
			}
			oldp = p;
			p = strchr(p, '%');
			APPEND(p - oldp - 1, oldp);
		} while (p);
		APPEND(strlen(p) + 1, p);
	}
	* result = res;
	return 0;
}

/**
 * spf_domainspec - parse the domainspec 
 *
 * @token: pointer to the string after the token
 * @domain: here the expanded domain string is stored (memory will be malloced)
 * @ip4cidr: the length of the IPv4 net (parsed if present in token, -1 if none given)
 * @ip6cidr: same for IPv6 net length
 *
 * returns:	 0 if everything is ok
 *		-1 on error (ENOMEM)
 *		SPF_TEMP_ERROR, SPF_HARD_ERROR
 */
int
spf_domainspec(char *token, char **domain, int *ip4cidr, int *ip6cidr)
{
	*ip4cidr = -1;
	*ip6cidr = -1;
/* if there is nothing we don't need to do anything */
	if (!*token || WSPACE(*token)) {
		*domain = NULL;
		return 0;
/* search for a domain in token */
	} else if (*token == ':') {
		int i = 0;
		char *t = token;

		t++;
		while (*t && !WSPACE(*t) &&
				(((*t >='a') && (*t <='z')) || ((*t >='A') && (*t <='Z')) ||
				((*t >='0') && (*t <='9')) || (*t == '-') || (*t == '_') ||
				((*t == '%') && !i) || ((*t == '{') && (i == 1)) || (*t == '.') ||
				((i == 2) && ((*t == '}') || (*t == ',') || (*t == '+') ||
				(*t == '/') || (*t == '='))))) {
			t++;
			switch (*t) {
				case '%':	i = 1;
						break;
				case '{':	if (*(t - 1) != '%') {
							return SPF_HARD_ERROR;
						}
						i = 2;
						break;
				case '}':	i = 0;
			}
		}
		if (*t && (*t != '/') && !WSPACE(*t)) {
			return SPF_HARD_ERROR;
		}
		if (t != token) {
			char o;
			int i;

			o = *t;
			*t = '\0';
			if ((i = spf_makro(t, token, 0, domain))) {
				return i;
			}
			*t = o;
			token = t;
		}
	}
/* check if there is a cidr length given */
	if (*token == '/') {
		char *c = NULL;

		*ip4cidr = strtol(token + 1, &c, 10);
		if ((*ip4cidr < 8) || (*ip4cidr > 32) || (!WSPACE(*c) && (*c != '/'))) {
			return SPF_HARD_ERROR;
		}
		if (*c++ != '/') {
			*ip6cidr = -1;
		} else {
			if (*c++ != '/') {
				return SPF_HARD_ERROR;
			}
			*ip6cidr = strtol(c, &c, 10);
			if ((*ip6cidr < 8) || (*ip6cidr > 128) || !WSPACE(*c)) {
				return SPF_HARD_ERROR;
			}
		}
	} else if (!WSPACE(*token) && *token) {
		return SPF_HARD_ERROR;
	}
	return 0;
}
