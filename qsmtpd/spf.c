/** \file qsmtpd/spf.c
 \brief functions to query and parse SPF entries
 */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#define __USE_GNU
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "qsmtpd.h"
#include "antispam.h"
#include "sstring.h"
#include "libowfatconn.h"
#include "match.h"
#include "netio.h"
#include "fmt.h"
#include "mime.h"

static const char spf_delimiters[] = ".-+,/_=";

#define WRITEl(fd, s, l) if ( (rc = write((fd), (s), (l))) < 0 ) return rc
#define WRITE(fd, s) WRITEl((fd), (s), strlen(s))

/**
 * print "Received-SPF:" to message header
 *
 * @param fd file descriptor of message body
 * @param spf SPF status of mail transaction
 * @return 0 if everything goes right, -1 on write error
 */
int
spfreceived(int fd, const int spf)
{
	const char *result[] = {
		"None",
		"Pass",
		"Neutral",
		"SoftFail",
		"Fail",
		"PermError",
		"PermError",
		"TempError",
		"PermError"
	};

	int rc;
	char clientip[INET6_ADDRSTRLEN];

	if (spf == SPF_IGNORE)
		return 0;

	WRITE(fd, "Received-SPF: ");
	WRITE(fd, result[spf]);

	if ((spf == SPF_HARD_ERROR) && (xmitstat.spfexp != NULL)) {
		WRITE(fd, " ");
		WRITE(fd, xmitstat.spfexp);
	}

	WRITE(fd, " (");
	WRITEl(fd, heloname.s, heloname.len);
	WRITE(fd, ": ");

	if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
		inet_ntop(AF_INET, &(xmitstat.sremoteip.s6_addr32[3]), clientip, sizeof(clientip));
	} else {
		inet_ntop(AF_INET6, &xmitstat.sremoteip, clientip, sizeof(clientip));
	}

	switch (spf) {
	case SPF_FAIL_MALF:
	case SPF_FAIL_NONEX:
	case SPF_HARD_ERROR:
		WRITE(fd, "domain of\n\t");
		WRITEl(fd, xmitstat.mailfrom.s, xmitstat.mailfrom.len);
		WRITE(fd, " uses mechanism not recognized by this client");
		if ((xmitstat.spfexp != NULL) && (strchr(xmitstat.spfexp, '%') != NULL)) {
			WRITE(fd, ", unsafe characters may have been replaced by '%'");
		}
		WRITE(fd, ")\n");
		break;
	case SPF_TEMP_ERROR:
		WRITE(fd, "error in processing during lookup of ");
		WRITEl(fd, xmitstat.mailfrom.s, xmitstat.mailfrom.len);
		WRITE(fd, ": DNS problem)\n");
		break;
	case SPF_NONE:
		WRITE(fd, "domain of ");
		WRITEl(fd, xmitstat.mailfrom.s, xmitstat.mailfrom.len);
		WRITE(fd, " does not designate permitted sender hosts)\n");
		return 0;
	case SPF_SOFTFAIL:
	case SPF_FAIL_PERM:
		WRITE(fd, "domain of ");
		WRITEl(fd, xmitstat.mailfrom.s, xmitstat.mailfrom.len);
		WRITE(fd, " does not designate ");
		WRITE(fd, clientip);
		WRITE(fd, " as permitted sender)\n");
		break;
	case SPF_NEUTRAL:
		WRITE(fd, clientip);
		WRITE(fd, " is neither permitted nor denied by domain of ");
		WRITEl(fd, xmitstat.mailfrom.s, xmitstat.mailfrom.len);
		WRITE(fd, ")\n");
		break;
	case SPF_PASS:
		WRITE(fd, "domain of ");
		WRITEl(fd, xmitstat.mailfrom.s, xmitstat.mailfrom.len);
		WRITE(fd, " designates ");
		WRITE(fd, clientip);
		WRITE(fd, " as permitted sender)\n");
		break;
	default:
		assert(0);
		errno = EFAULT;
		return -1;
	}

	WRITE(fd, "\treceiver=");
	WRITEl(fd, heloname.s, heloname.len);
	WRITE(fd, "; client-ip=");
	WRITE(fd, clientip);
	if (xmitstat.spfmechanism != NULL) {
		WRITE(fd, "; mechanism=");
		WRITE(fd, xmitstat.spfmechanism);
	}
	WRITE(fd, ";\n\thelo=");
	WRITEl(fd, xmitstat.helostr.s, xmitstat.helostr.len);
	WRITE(fd, "; envelope-from=\"");
	WRITEl(fd, xmitstat.mailfrom.s, xmitstat.mailfrom.len);
	WRITE(fd, "\"\n");
	return 0;
}

/**
 * parse the options in an SPF macro
 *
 * @param token token to parse
 * @param num DIGIT
 * @param r if reverse is given
 * @param delim bitmask of delimiters
 * @return number of bytes parsed, -1 on error
 */
static int
spf_makroparam(char *token, int *num, int *r, int *delim)
{
	int res = 0;
	const char *t;

	*r = 0;
	*num = -1;
	*delim = 1;	/* '.' is the default delimiter */

	if ((*token >= '0') && (*token <= '9')) {
		*num = 0;
		do {
			*num = *num * 10 + (*token++ - '0');
			res++;
		} while ((*token >= '0') && (*token <= '9'));
		if (!*num) {
			errno = EINVAL;
			return -1;
		}
	} else {
		*num = 255;
	}
	if (*token == 'r') {
		token++;
		res++;
		*r = 1;
	}
	do {
		int k;

		t = token;
		for (k = 0; k < strlen(spf_delimiters); k++) {
			if (spf_delimiters[k] == *token) {
				*delim |= (1 << k);
				token++;
				res++;
			}
		}
	} while (t != token);

	return res;
}

static int
urlencode(char *token, char **result)
{
	char *res = NULL;
	char *last = token;	/* the first unencoded character in the current chunk */
	unsigned int len = 0;

	while (*token) {
		char *tmp;
		unsigned int newlen;
		char n;

		if (!(((*token >= 'a') && (*token <= 'z')) || ((*token >= 'A') && (*token <= 'Z')) ||
						((*token >= 'A') && (*token <= 'Z')))) {
			switch (*token) {
				case '-':
				case '_':
				case '.':
				case '!':
				case '~':
				case '*':
				case '\'':
				case '(':
				case ')':	break;
				default:	newlen = len + 3 + (token - last);
						tmp = realloc(res, newlen + 1);
						if (!tmp) {
							free(res);
							return -1;
						}
						res = tmp;
						memcpy(res + len, last, token - last);
						len = newlen;
						res[len - 3] = '%';
						n = (*token & 0xf0) >> 4;
						res[len - 2] = ((n > 9) ? 'A' - 10 : '0') + n;
						n = (*token & 0x0f);
						res[len - 1] = ((n > 9) ? 'A' - 10 : '0') + n;
						last = token + 1;
			}
		}
		token++;
	}
	if (!len) {
		/* nothing has changed */
		*result = token;
		return 0;
	}
	if (token - last) {
		/* there is data behind the last encoded char */
		unsigned int newlen = len + 3 + (token - last);
		char *tmp;

		tmp = realloc(res, newlen + 1);
		if (!tmp) {
			free(res);
			return -1;
		}
		res = tmp;
		memcpy(res + len, last, token - last);
		len = newlen;
	}
	res[len] = '\0';
	*result = res;
	return 0;
}

/**
 * append a makro content to the result
 *
 * @param res result string
 * @param l current length of res
 * @param s the raw string to appended, does not need to be terminated by '\0'
 * @param sl strlen(s), must not be 0
 * @param num DIGIT
 * @param r Bit 1: reverse of not; Bit 2: use URL encoding
 * @param delim bit mask of delimiters
 * @return 0 on success, -1 on error
 */
static int
spf_appendmakro(char **res, unsigned int *l, const char *const s, const unsigned int sl, int num,
			const int r, const int delim)
{
	int dc = 0;	/* how many delimiters we find */
	unsigned int nl;
	char *start;
	char *r2;
	unsigned int oldl = *l;
	char *news = malloc(sl + 1);

	if (!news)
		return -1;
	memcpy(news, s, sl);
	news[sl] = '\0';
/* first: go and replace all delimiters with '.' */
	/* delim == 1 means only '.' is delimiter so we only have to count them */
	if (delim == 1) {
		int j = sl;

		while (--j >= 0) {
			 if (s[j] == '.') {
			 	dc++;
			 }
		}
	} else {
		char actdelim[8];
		unsigned int k = 0;
		int m;
		char *d = news;

		/* This constructs the list of actually used delimiters. */
		for (m = strlen(spf_delimiters); m >= 0; m--) {
			if (delim & (1 << m))
				actdelim[k++] = spf_delimiters[m];
		}
		actdelim[k] = '\0';

		while ( (d = strpbrk(d, actdelim)) ) {
			*d++ = '.';
			dc++;
		}
	}
	if (r & 1) {
		char *tmp, *dot;
		unsigned int v;

		start = news;
		if (num > dc) {
			v = sl;
			num = dc + 1;
		} else {
			for (v = num; v > 0; v--) {
				start = strchr(start, '.') + 1;
			}
			v = start - news - 1;
		}

		tmp = malloc(v + 1);
		dot = news;
		nl = v;
		dc = num - 1;

		while (--dc >= 0) {
			unsigned int o = strchr(dot, '.') - dot;

			memcpy(tmp + v - o, dot, o);
			tmp[v - o - 1] = '.';
			dot += o + 1;
			v -= o + 1;
		}
		if ((start = strchr(dot, '.'))) {
			v = start - dot;
		} else {
			v = strlen(dot);
		}
		memcpy(tmp, dot, v);
		free(news);
		start = news = tmp;
	} else {
		start = news;
		if (dc >= num) {
			while (dc-- >= num) {
				start = strchr(start, '.') + 1;
			}
			nl = strlen(start);
		} else {
			nl = sl;
		}
	}

	if (r & 2) {
		if (urlencode(start, &start)) {
			free(*res);
			free(news);
			return -1;
		}
		nl = strlen(start);
	}

	*l += nl;
	r2 = realloc(*res, *l);
	if (!r2) {
		free(*res);
		free(news);
		return -1;
	}
	*res = r2;
	memcpy(*res + oldl, start, nl);
	free(news);

	return 0;
}

#define APPEND(addlen, addstr) \
	{\
		char *r2;\
		unsigned int oldl = *l;\
		\
		*l += addlen;\
		r2 = realloc(*res, *l);\
		if (!r2) { free(*res); return -1;}\
		*res = r2;\
		memcpy(*res + oldl, addstr, addlen);\
	}

#define PARSEERR	do { free(*res); return SPF_HARD_ERROR; } while (0)

/**
 * expand a SPF makro letter
 *
 * @param p the token to parse
 * @param domain the current domain string
 * @param ex if this is an exp string
 * @param res the resulting string is stored here
 * @param l offset into res
 * @return number of bytes parsed, -1 on error
 */
static int
spf_makroletter(char *p, const char *domain, int ex, char **res, unsigned int *l)
{
	char *q = p, ch;
	int offs, num, r, delim;

	ch = *p++;
	offs = spf_makroparam(p, &num, &r, &delim);
	p += offs;
	if ((offs < 0) || (*p != '}'))
		PARSEERR;
	switch (ch) {
		case 'S':	r |= 0x2;
		case 's':	if (xmitstat.mailfrom.len) {
					if (spf_appendmakro(res, l, xmitstat.mailfrom.s,
					    				xmitstat.mailfrom.len,
									num, r, delim))
						return -1;
				} else {
					unsigned int senderlen = 12 + HELOLEN;
					char *sender = malloc(senderlen--);

					if (!sender)
						return -1;
					memcpy(sender, "postmaster@", 11);
					memcpy(sender + 11, HELOSTR, HELOLEN + 1);
					r = spf_appendmakro(res, l, sender, senderlen, num, r, delim);
					free(sender);
					if (r)
						return -1;
				}
				break;
		case 'L':	r |= 0x2;
		case 'l':	if (xmitstat.mailfrom.len) {
					char *at = strchr(xmitstat.mailfrom.s, '@');

					if (spf_appendmakro(res, l, xmitstat.mailfrom.s,
					    					at - xmitstat.mailfrom.s,
										num, r, delim)) {
						return -1;
					}
				} else {
					/* we can do it the short way here, this can't be changed by
					 * any combination of makro flags */
					APPEND(10, "postmaster");
				}
				break;
		case 'O':	r |= 0x2;
		case 'o':	if (xmitstat.mailfrom.len) {
					char *at = strchr(xmitstat.mailfrom.s, '@');
					unsigned int offset =
							at - xmitstat.mailfrom.s + 1;

					/* the domain name is always the same in normal and url-ified form */
					if (spf_appendmakro(res, l, at + 1, xmitstat.mailfrom.len - offset,
					    				num, r, delim))
						return -1;
				} else {
					if (spf_appendmakro(res, l, HELOSTR, HELOLEN, num, r, delim))
						return -1;
				}
				break;
		case 'D':	r |= 0x2;
		case 'd':	if (spf_appendmakro(res, l, domain, strlen(domain), num, r, delim))
					return -1;
				break;
		case 'C':
		case 'c':	if (!ex)
					PARSEERR;
				if (!IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
					char a[INET6_ADDRSTRLEN];

					inet_ntop(AF_INET6, &xmitstat.sremoteip, a, sizeof(a));
					APPEND(strlen(a), a);
					break;
				}
				/* fallthrough */
		case 'I':
		case 'i':	if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
					char ip[INET_ADDRSTRLEN];

					inet_ntop(AF_INET,
							&(xmitstat.sremoteip.s6_addr32[3]),
							ip, sizeof(ip));

					if (spf_appendmakro(res, l, ip, strlen(ip), num, r, delim))
						return -1;
				} else {
					char ip[64];

					dotip6(ip);
					ip[63] = '\0';
					if (spf_appendmakro(res, l, ip, 63, num, r, delim))
						return -1;
				}
				break;
		case 'T':
		case 't':	if (!ex) {
					PARSEERR;
				} else {
					char t[ULSTRLEN];

					ultostr(time(NULL), t);
					APPEND(strlen(t), t);
				}
				break;
		case 'P':
		case 'p':	if (xmitstat.remotehost.len) {
					if (spf_appendmakro(res, l, xmitstat.remotehost.s,
					    			xmitstat.remotehost.len, num, r, delim))
						return -1;
				} else {
					APPEND(7, "unknown");
				}
				break;
		case 'R':
		case 'r':	if (!ex) {
					PARSEERR;
				}
				if (spf_appendmakro(res, l, heloname.s, heloname.len, num, r, delim))
					return -1;
				break;
		case 'V':
		case 'v':	if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
					if (delim & 2) {
						if (r) {
							if (num == 1) {
								APPEND(2, "in");
							} else {
								APPEND(7, "addr.in");
							}
						} else {
							if (num == 1) {
								APPEND(4, "addr");
							} else {
								APPEND(7, "in.addr");
							}
						}
					} else {
						APPEND(7, "in-addr");
					}
				} else {
					APPEND(3, "ip6");
				}
				break;
		case 'H':
		case 'h':	if (spf_appendmakro(res, l, HELOSTR, HELOLEN, num, r, delim))
					return -1;
				break;
		default:	APPEND(7, "unknown");
	}
	return p - q;
}

#undef APPEND
#define APPEND(addlen, addstr) \
	{\
		char *r2;\
		unsigned int oldl = l;\
		\
		l += addlen;\
		r2 = realloc(res, l);\
		if (!r2) { free(res); return -1;}\
		res = r2;\
		memcpy(res + oldl, addstr, addlen);\
	}

#undef PARSEERR
#define PARSEERR	{free(res); return SPF_HARD_ERROR;}


/**
 * expand a SPF makro
 *
 * @param token the token to parse
 * @param domain the current domain string
 * @param ex if this is an exp string
 * @param result the resulting string is stored here
 * @return 0 on success, -1 on ENOMEM, SPF_{HARD,TEMP}_ERROR on problems
 *
 * not static, is called from targets/testspf.c
 */
int
spf_makro(char *token, const char *domain, int ex, char **result)
{
	char *res;
	char *p;
	unsigned int l;
	size_t toklen = 0;

	if (ex == 1) {
		toklen = strlen(token);
	} else {
		p = token;
		while ((*p != '\0') && ((ex == 1) || !WSPACE(*p)) && (*p != '/')) {
			p++;
			toklen++;
		}
	}

	p = memchr(token, '%', toklen);

	if (p == NULL) {
		l = toklen + 1;

		res = malloc(l);
		if (!res) {
			return -1;
		}
		memcpy(res, token, toklen);
		res[toklen] = '\0';
	} else {
		l = p - token;

		res = malloc(l);
		if (!res) {
			return -1;
		}
		memcpy(res, token, l);
		do {
			int z;

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
				case '{':	z = spf_makroletter(++p, domain, ex, &res, &l);
						if ((z < 0) || (z == SPF_HARD_ERROR)) {
							return z;
						} else if (!z || (*(p + z) != '}')) {
							PARSEERR;
						}
						p += z + 1;
						break;
				default:	APPEND(1, "%");
						/* no p++ here! */
			}
			if (*p != '%') {
				const char *oldp = p;
				p = strchr(p, '%');
				if (((p != NULL) && (p > token + toklen)) || (p == NULL))
					p = token + toklen;

				if (p != oldp)
					APPEND(p - oldp, oldp);
			}
		} while (p && (p < token + toklen) && !WSPACE(*p));
		APPEND(1, "");
	}
	*result = res;
	return 0;
}

enum spf_makro_expansion {
	SPF_MAKRO_NONE,
	SPF_MAKRO_PERCENT,
	SPF_MAKRO_BRACE,
	SPF_MAKRO_LETTER,
	SPF_MAKRO_TRANSFORMER,
	SPF_MAKRO_DELIMITER
};

/**
 * parse the domainspec
 *
 * @param token pointer to the string after the token
 * @param dparam domain here the expanded domain string is stored (memory will be malloced)
 * @param ip4cidr the length of the IPv4 net (parsed if present in token, -1 if none given)
 * @param ip6cidr same for IPv6 net length
 * @returns:	 0 if everything is ok
 *		-1 on error (ENOMEM)
 *		SPF_TEMP_ERROR, SPF_HARD_ERROR
 */
static int
spf_domainspec(const char *domain, char *token, char **domainspec, int *ip4cidr, int *ip6cidr)
{
	*ip4cidr = -1;
	*ip6cidr = -1;
/* if there is nothing we don't need to do anything */
	*domainspec = NULL;
	if (!*token || WSPACE(*token)) {
		return 0;
/* search for a domain in token */
	} else if (*token != '/') {
		enum spf_makro_expansion i = SPF_MAKRO_NONE;
		char *t = token;

		while (*t && !WSPACE(*t) && (*t != '/')) {

			switch (i) {
			case SPF_MAKRO_NONE:
				if (*t == '%') {
					i = SPF_MAKRO_PERCENT;
					t++;
					/* fallthrough */
				} else {
					if ((*t < 0x21) || (*t > 0x7e))
						return SPF_HARD_ERROR;
					t++;
					continue;
				}
			case SPF_MAKRO_PERCENT:
				switch (*t) {
				case '%':
				case '_':
				case '-':
					i = SPF_MAKRO_NONE;
					t++;
					continue;
				case '{':
					i = SPF_MAKRO_BRACE;
					break;
				default:
					return SPF_HARD_ERROR;
				}
				t++;
				/* fallthrough */
			case SPF_MAKRO_BRACE:
				/* expecting spf-makro-letter now */
				switch (toupper(*t)) {
				case 'S':
				case 'L':
				case 'O':
				case 'D':
				case 'I':
				case 'P':
				case 'H':
				case 'C':
				case 'R':
				case 'T':
				case 'V':
					i = SPF_MAKRO_LETTER;
					t++;
					break;
				default:
					return SPF_HARD_ERROR;
				}
				/* fallthrough */
			case SPF_MAKRO_LETTER:
			case SPF_MAKRO_TRANSFORMER:
				/* expecting transformer, delimiter, or '}' */
				switch (*t) {
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					i = SPF_MAKRO_TRANSFORMER;
					t++;
					continue;
				};
				if (*t == 'r')
					t++;
				/* fallthrough */
			case SPF_MAKRO_DELIMITER:
				switch (*t) {
				case '.':
				case '-':
				case '+':
				case ',':
				case '/':
				case '_':
				case '=':
					i = SPF_MAKRO_DELIMITER;
					t++;
					continue;
				case '}':
					i = SPF_MAKRO_NONE;
					t++;
					continue;
				default:
					return SPF_HARD_ERROR;
				}
			}
		}

		if (i != SPF_MAKRO_NONE)
			return SPF_HARD_ERROR;

		if (t != token) {
			if ((i = spf_makro(token, domain, 0, domainspec))) {
				return i;
			}
			token = t;
		}
	}
/* check if there is a cidr length given */
	if (*token == '/') {
		char *c = token + 1;

		if (*c != '/') {
			*ip4cidr = strtol(c, &c, 10);
			if ((*ip4cidr < 8) || (*ip4cidr > 32) || (!WSPACE(*c) && (*c != '/') && (*c != '\0'))) {
				free(*domainspec);
				return SPF_HARD_ERROR;
			}
		} else {
			c--;
		}
		if (*c++ != '/') {
			*ip6cidr = -1;
		} else {
			if (*c++ != '/') {
				free(*domainspec);
				return SPF_HARD_ERROR;
			}
			*ip6cidr = strtol(c, &c, 10);
			if ((*ip6cidr < 8) || (*ip6cidr > 128) || !(WSPACE(*c) || (*c == '\0'))) {
				free(*domainspec);
				return SPF_HARD_ERROR;
			}
		}
	}
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
static int
spfmx(const char *domain, char *token)
{
	int ip6l, ip4l, i;
	struct ips *mx, *allmx;
	char *domainspec;

	if ( (i = spf_domainspec(domain, token, &domainspec, &ip4l, &ip6l)) ) {
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
		freeips(mx);
		return SPF_NONE;
	}
	allmx = mx;
	if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
		while (mx) {
			if (IN6_IS_ADDR_V4MAPPED(&(mx->addr)) &&
					ip4_matchnet(&xmitstat.sremoteip,
							(struct in_addr *) &(mx->addr.s6_addr32[3]), ip4l)) {
				freeips(allmx);
				return SPF_PASS;
			}
			mx = mx->next;
		}
	} else {
		while (mx) {
			if (ip6_matchnet(&xmitstat.sremoteip, &mx->addr, ip6l)) {
				freeips(allmx);
				return SPF_PASS;
			}
			mx = mx->next;
		}
	}
	freeips(allmx);
	return SPF_NONE;
}

static int
spfa(const char *domain, char *token)
{
	int ip6l, ip4l, i, r = 0;
	struct ips *ip, *thisip;
	char *domainspec;

	if ( (i = spf_domainspec(domain, token, &domainspec, &ip4l, &ip6l)) ) {
		return i;
	}
	if (ip4l < 0) {
		ip4l = 32;
	}
	if (ip6l < 0) {
		ip6l = 128;
	}
	if (domainspec) {
		i = ask_dnsaaaa(domainspec, &ip);
		free(domainspec);
	} else {
		i = ask_dnsaaaa(domain, &ip);
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

static int
spfexists(const char *domain, char *token)
{
	int ip6l, ip4l, i, r = 0;
	char *domainspec;

	if ( (i = spf_domainspec(domain, token, &domainspec, &ip4l, &ip6l)) ) {
		return i;
	}
	if ((ip4l > 0) || (ip6l > 0) || !domainspec) {
		return SPF_HARD_ERROR;
	}
	i = ask_dnsa(domainspec, NULL);
	free(domainspec);

	switch (i) {
		case 0:	r = SPF_PASS;
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

static int
spfptr(const char *domain, char *token)
{
	int ip6l, ip4l, i, r = 0;
	struct ips *ip, *thisip;
	char *domainspec;

	if (!xmitstat.remotehost.len) {
		return SPF_NONE;
	}
	if ( (i = spf_domainspec(domain, token, &domainspec, &ip4l, &ip6l)) ) {
		return i;
	}
	if ((ip4l > 0) || (ip6l > 0)) {
		free(domainspec);
		return SPF_HARD_ERROR;
	}
	if (domainspec) {
		i = ask_dnsaaaa(domainspec, &ip);
		free(domainspec);
	} else {
		i = ask_dnsaaaa(domain, &ip);
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

static int
spfip4(const char *domain)
{
	const char *sl = domain;
	struct in_addr net;
	unsigned long u;
	char ip4buf[INET_ADDRSTRLEN];
	size_t ip4len;

	if (!IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip))
		return SPF_NONE;

	while (((*sl >= '0') && (*sl <= '9')) || (*sl == '.')) {
		sl++;
	}

	ip4len = sl - domain;
	if ((ip4len >= sizeof(ip4buf)) || (ip4len < 7))
		return SPF_HARD_ERROR;

	if (*sl == '/') {
		char *q;

		u = strtoul(sl + 1, &q, 10);
		if ((u < 8) || (u > 32) || (!WSPACE(*q) && (*q != '\0')))
			return SPF_HARD_ERROR;
		sl = q;
	} else if (WSPACE(*sl) || !*sl) {
		u = 32;
	} else {
		return SPF_HARD_ERROR;
	}

	memset(ip4buf, 0, sizeof(ip4buf));
	memcpy(ip4buf, domain, ip4len);

	if (!inet_pton(AF_INET, ip4buf, &net))
		return SPF_HARD_ERROR;

	return ip4_matchnet(&xmitstat.sremoteip, &net, u) ? SPF_PASS : SPF_NONE;
}

static int
spfip6(const char *domain)
{
	const char *sl = domain;
	struct in6_addr net;
	unsigned long u;
	char ip6buf[INET6_ADDRSTRLEN];
	size_t ip6len;

	if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip))
		return SPF_NONE;
	while (((*sl >= '0') && (*sl <= '9')) || ((*sl >= 'a') && (*sl <= 'f')) ||
					((*sl >= 'A') && (*sl <= 'F')) || (*sl == ':') || (*sl == '.')) {
		sl++;
	}

	ip6len = sl - domain;
	if ((ip6len >= sizeof(ip6buf)) || (ip6len < 3))
		return SPF_HARD_ERROR;

	if (*sl == '/') {
		char *endp;
		u = strtoul(sl + 1, &endp, 10);
		if ((u < 8) || (u > 128) || (!WSPACE(*endp) && (*endp != '\0')))
			return SPF_HARD_ERROR;
		sl = endp;
	} else if (WSPACE(*sl) || !*sl) {
		u = 128;
	} else {
		return SPF_HARD_ERROR;
	}

	memset(ip6buf, 0, sizeof(ip6buf));
	memcpy(ip6buf, domain, ip6len);

	if (!inet_pton(AF_INET6, ip6buf, &net))
		return SPF_HARD_ERROR;

	return ip6_matchnet(&xmitstat.sremoteip, &net, (unsigned char) (u & 0xff)) ? SPF_PASS : SPF_NONE;
}

/**
 * @brief lookup TXT record taking SPF specialities into account
 * @param txt result pointer
 * @param domain domain token to look up
 * @returns the same error codes as dnstxt()
 * 
 * This will take two SPF specific contraints into account:
 * - trailing dots are ignored
 * - if domain is longer than 253 characters parts are removed until it is shorter
 */
static int
txtlookup(char **txt, const char *domain)
{
	char lookup[256];
	unsigned int offs = 0;
	size_t len = strlen(domain);

	while ((len > 0) && (domain[len - 1] == '.')) {
		len--;
	}

	if (len == 0) {
		errno = EINVAL;
		return -1;
	}

	while (len - offs > 253) {
		const char *dot = strchr(domain + offs, '.');
		if (dot == NULL) {
			errno = EINVAL;
			return -1;
		}

		offs = (dot - domain) + 1;
	}

	memcpy(lookup, domain + offs, len - offs);
	lookup[len - offs] = '\0';

	return dnstxt(txt, lookup);
}

/**
 * look up SPF records for domain
 *
 * @param domain no idea what this might be for
 * @param rec recursion level
 * @return one of the SPF_* constants defined in include/antispam.h or -1 on ENOMEM
 */
static int
spflookup(const char *domain, const int rec)
{
	char *txt, *token, *valid = NULL, *redirect = NULL;
	int i, result = SPF_NONE, prefix;
	const char *mechanism = NULL;

	if (rec >= 20)
		return SPF_HARD_ERROR;

	/* don't enforce valid domains on redirects */
	if (!rec && domainvalid(domain))
		return SPF_FAIL_MALF;

	if (rec > 0) {
		i = txtlookup(&txt, domain);
	} else {
		i = dnstxt(&txt, domain);
	}

	if (i) {
		switch (errno) {
			case ENOENT:	return SPF_NONE;
			case ETIMEDOUT:
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
		if (!*token) {
			mechanism = "default";
			break;
		}
		switch(*token) {
			case '-':	token++; prefix = SPF_FAIL_PERM; break;
			case '~':	token++; prefix = SPF_SOFTFAIL; break;
			case '+':	token++; prefix = SPF_PASS; break;
			case '?':	token++; prefix = SPF_NEUTRAL; break;
			default:	if (((*token >= 'a') && (*token <= 'z')) ||
								((*token >= 'A') && (*token <= 'Z'))) {
						prefix = SPF_PASS;
					} else {
						free(txt);
						return SPF_HARD_ERROR;
					}
		}
		if (!strncasecmp(token, "mx", 2) &&
					(WSPACE(*(token + 2)) || !*(token + 2) || (*(token + 2) == ':') ||
						(*(token + 2) == '/'))) {
			token += 2;
			if (*token == ':')
				token++;
			result = spfmx(domain, token);
			mechanism = "MX";
		} else if (!strncasecmp(token, "ptr", 3) &&
				(WSPACE(*(token + 2)) || !*(token + 2) || (*(token + 2) == ':'))) {
			token += 3;
			if (*token == ':')
				token++;
			result = spfptr(domain, token);
			mechanism = "PTR";
		} else if (!strncasecmp(token, "exists:", 7)) {
			token += 7;
			result = spfexists(domain, token);
			mechanism = "exists";
		} else if (!strncasecmp(token, "all", 3) && (WSPACE(*(token + 3)) || !*(token + 3))) {
			result = SPF_PASS;
			mechanism = "all";
		} else if (((*token == 'a') || (*token == 'A')) &&
					(WSPACE(*(token + 1)) || !*(token + 1) || (*(token + 1) == ':'))) {
			if (*(++token) == ':')
				token++;
			result = spfa(domain, token);
			mechanism = "A";
		} else if (!strncasecmp(token, "ip4:", 4)) {
			token += 4;
			result = spfip4(token);
			mechanism = "IP4";
		} else if (!strncasecmp(token, "ip6:", 4)) {
			token += 4;
			result = spfip6(token);
			mechanism = "IP6";
		} else if (!strncasecmp(token, "include:", 8)) {
			char *n = NULL;

			token += 8;

			result = spf_makro(token, domain, 0, &n);

			if (result == 0) {
				result = spflookup(n, rec + 1);
				free(n);
			}

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

			mechanism = "include";
		} else if (!strncasecmp(token, "redirect=", 9)) {
			token += 9;
			if (!redirect) {
				redirect = token;
			}
		} else if (!strncasecmp(token, "exp=", 4)) {
			token += 4;
			/* ignore them for now, will be checked later on failure */
		} else {
			/* This is an invalid token. Go back to the last whitespace
			 * and copy that to spfexp so it can be recorded in the
			 * Received-SPF line if the user still accepts the mail. We
			 * know there is at least one whitespace after the v=spf1
			 * token. Then go back until the next whitespace or to the
			 * end, replace any unsafe char by '?' */

			char *tokenend;

			prefix = SPF_HARD_ERROR;
			result = SPF_PASS;

			tokenend = token;
			while (!WSPACE(*(token - 1)))
				token--;

			while (!WSPACE(*tokenend))
				tokenend++;

			xmitstat.spfexp = malloc(tokenend - token + 1);
			if(xmitstat.spfexp != NULL) {
				const size_t toklen = tokenend - token;
				size_t tpos;

				xmitstat.spfexp[toklen] = '\0';

				for (tpos = 0; tpos < toklen; tpos++) {
					/* filter out everything that is not a valid entry in a MIME header */
					if (TSPECIAL(token[tpos]) || (token[tpos] <= ' ') || (token[tpos] >= 127))
						xmitstat.spfexp[tpos] = '%';
					else
						xmitstat.spfexp[tpos] = token[tpos];
				}
			}

			break;
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
	if (result < 0) {
		free(txt);
		return result;
	}
	if (result == SPF_PASS) {
		if (SPF_FAIL(prefix)) {
			char *ex = strcasestr(txt, "exp=");

			if (ex != NULL) {
				char *target;

				i = spf_makro(ex + 4, domain, 0, &target);
				if (i == 0) {
					size_t dlen = strlen(target);
					while ((dlen > 0) && (target[dlen - 1] == '.')) {
						target[--dlen] = '\0';
					}
					if (dlen > 0) {
						char *exp;
						i = txtlookup(&exp, target);
						if (i == 0) {
							i = spf_makro(exp, domain, 1, &xmitstat.spfexp);
							free(exp);
						}
					}
					free(target);
				}
			}
		}
		free(txt);
		xmitstat.spfmechanism = mechanism;
		return prefix;
	}

	if (redirect) {
		char *domspec;
		int i4, i6;

		result = spf_domainspec(domain, redirect, &domspec, &i4, &i6);

		if (result == 0) {
			if ((i4 != -1) || (i6 != -1))
				result = SPF_HARD_ERROR;
			else
				result = spflookup(domspec, rec + 1);
			free(domspec);
		}
	} else {
		result = SPF_NEUTRAL;
	}
	free(txt);
	return result;
}

/**
 * look up SPF records for domain
 *
 * This works a like the check_host in the SPF draft but takes two arguments less. The remote ip and the full
 * sender address can be taken directly from xmitstat.
 *
 * @param domain no idea what this might be for ;)
 * @return one of the SPF_* constants defined in include/antispam.h
 */
int
check_host(const char *domain)
{
	return spflookup(domain, 0);
}
