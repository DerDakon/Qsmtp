/** \file qsmtpd/spf.c
 \brief functions to query and parse SPF entries
 */

#define _GNU_SOURCE /* for strcasestr() */

#include <qsmtpd/antispam.h>

#include <fmt.h>
#include <libowfatconn.h>
#include <match.h>
#include <mime_chars.h>
#include <netio.h>
#include <qsmtpd/qsmtpd.h>
#include <sstring.h>

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
	const char *spfdomain = (xmitstat.mailfrom.len == 0) ? HELOSTR : xmitstat.mailfrom.s;
	const size_t spfdomainlen = (xmitstat.mailfrom.len == 0) ? HELOLEN : xmitstat.mailfrom.len;

	if (spf == SPF_IGNORE)
		return 0;

	WRITE(fd, "Received-SPF: ");
	WRITE(fd, result[spf]);

	if ((spf == SPF_FAIL_MALF) && (xmitstat.spfexp != NULL)) {
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
		WRITE(fd, "domain of\n\t");
		WRITEl(fd, spfdomain, spfdomainlen);
		WRITE(fd, " uses mechanism not recognized by this client");
		if ((xmitstat.spfexp != NULL) && (strchr(xmitstat.spfexp, '%') != NULL)) {
			WRITE(fd, ", unsafe characters may have been replaced by '%'");
		}
		WRITE(fd, ")\n");
		break;
	case SPF_HARD_ERROR:
	case SPF_TEMP_ERROR:
		WRITE(fd, "error in processing during lookup of ");
		WRITEl(fd, spfdomain, spfdomainlen);
		WRITE(fd, ": DNS problem)\n");
		break;
	case SPF_NONE:
		WRITE(fd, "domain of ");
		WRITEl(fd, spfdomain, spfdomainlen);
		WRITE(fd, " does not designate permitted sender hosts)\n");
		return 0;
	case SPF_SOFTFAIL:
	case SPF_FAIL_PERM:
		WRITE(fd, "domain of ");
		WRITEl(fd, spfdomain, spfdomainlen);
		WRITE(fd, " does not designate ");
		WRITE(fd, clientip);
		WRITE(fd, " as permitted sender)\n");
		break;
	case SPF_NEUTRAL:
		WRITE(fd, clientip);
		WRITE(fd, " is neither permitted nor denied by domain of ");
		WRITEl(fd, spfdomain, spfdomainlen);
		WRITE(fd, ")\n");
		break;
	case SPF_PASS:
		WRITE(fd, "domain of ");
		WRITEl(fd, spfdomain, spfdomainlen);
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
	WRITEl(fd, HELOSTR, HELOLEN);
	WRITE(fd, "; envelope-from=<");
	WRITEl(fd, xmitstat.mailfrom.s, xmitstat.mailfrom.len);
	WRITE(fd, ">\n");
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
spf_makroparam(const char *token, int *num, int *r, int *delim)
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
		size_t k;

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
urlencode(const char *token, char **result)
{
	char *res = NULL;
	const char *last = token;	/* the first unencoded character in the current chunk */
	unsigned int len = 0;
	const char *otoken = token;

	while (*token) {
		char *tmp;

		if (!(((*token >= 'a') && (*token <= 'z')) || ((*token >= 'A') && (*token <= 'Z')) ||
						((*token >= '0') && (*token <= '9')))) {
			unsigned int newlen;
			char n;

			switch (*token) {
			case '-':
			case '_':
			case '.':
			case '!':
			case '~':
			case '*':
			case '\'':
			case '(':
			case ')':
				break;
			default:
				/* we need to add the string in between and 3 characters: %xx */
				newlen = len + 3 + (token - last);
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
		*result = malloc(strlen(otoken) + 1);
		if (*result == NULL)
			return -1;
		strcpy(*result, otoken);
		return 0;
	}
	if (token - last) {
		/* there is data behind the last encoded char */
		unsigned int newlen = len + (token - last);
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
	char *urldata = NULL;

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
		if (tmp == NULL) {
			free(news);
			return -1;
		}
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
		if (urlencode(start, &urldata)) {
			free(*res);
			free(news);
			return -1;
		}
		nl = strlen(urldata);
		start = urldata;
	}

	*l += nl;
	r2 = realloc(*res, *l);
	if (!r2) {
		free(*res);
		free(news);
		free(urldata);
		return -1;
	}
	*res = r2;
	memcpy(*res + oldl, start, nl);
	free(news);
	free(urldata);

	return 0;
}

/**
 * build a list of validated domain names for the connected host
 * @param domainlist where to store the array
 * @return how many entries are in domainlist, negative on error
 *
 * If this functions returns 0 all lookups were successfully, but no
 * validated domain names were found.
 */
static int
validate_domain(char ***domainlist)
{
	char *rnames = NULL;
	int i, r;
	char *d;
	int cnt = 0;

	r = ask_dnsname(&xmitstat.sremoteip, &rnames);
	if (r <= 0)
		return r;

	if (r > 10)
		r = 10;

	assert(rnames != NULL);
	*domainlist = malloc(sizeof(**domainlist) * r);
	if (*domainlist == NULL) {
		free(rnames);
		errno = ENOMEM;
		return -1;
	}

	d = rnames;
	for (i = 0; i < r; i++) {
		struct in6_addr *ptrs;
		int j, k;

		if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip))
			k = ask_dnsa(d, &ptrs);
		else
			k = ask_dnsaaaa(d, &ptrs);
		if (k <= 0) {
			/* If a DNS error occurs while doing an A RR lookup, then
			 * that domain name is skipped and the search continues. */
			d += strlen(d) + 1;
			continue;
		}

		for (j = 0; j < k; j++) {
			if (IN6_ARE_ADDR_EQUAL(ptrs + j, &xmitstat.sremoteip)) {
				(*domainlist)[cnt] = strdup(d);
				if ((*domainlist)[cnt] == NULL) {
					while (cnt > 0) {
						free((*domainlist)[--cnt]);
					}
					free(*domainlist);
					free(rnames);
					free(ptrs);
					errno = ENOMEM;
					return -1;
				}
				cnt++;
				break;
			}
		}

		free(ptrs);

		d += strlen(d) + 1;
	}

	free(rnames);
	if (cnt == 0) {
		free(*domainlist);
		*domainlist = NULL;
	}

	return cnt;
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

#define PARSEERR	do { free(*res); return -SPF_FAIL_MALF; } while (0)

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
spf_makroletter(const char *p, const char *domain, int ex, char **res, unsigned int *l)
{
	const char *q = p;
	char ch;
	int offs, num, r, delim;

	ch = *p++;
	offs = spf_makroparam(p, &num, &r, &delim);
	p += offs;
	if ((offs < 0) || (*p != '}'))
		PARSEERR;

	if (isupper(ch))
		r |= 0x2;

	switch (tolower(ch)) {
	case 's':
		if (xmitstat.mailfrom.len) {
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
	case 'l':
		if (xmitstat.mailfrom.len) {
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
	case 'o':
		if (xmitstat.mailfrom.len) {
			char *at = strchr(xmitstat.mailfrom.s, '@');
			unsigned int offset = at - xmitstat.mailfrom.s + 1;

			/* the domain name is always the same in normal and url-ified form */
			if (spf_appendmakro(res, l, at + 1, xmitstat.mailfrom.len - offset,
					num, r, delim))
				return -1;
		} else {
			if (spf_appendmakro(res, l, HELOSTR, HELOLEN, num, r, delim))
				return -1;
		}
		break;
	case 'd':
		if (spf_appendmakro(res, l, domain, strlen(domain), num, r, delim))
			return -1;
		break;
	case 'c':
		if (!ex)
			PARSEERR;
		if (!IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
			char a[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET6, &xmitstat.sremoteip, a, sizeof(a));
			APPEND(strlen(a), a);
			break;
		}
		/* fallthrough */
	case 'i':
		if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
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
			if (spf_appendmakro(res, l, ip, 63, num, !r, delim))
				return -1;
		}
		break;
	case 't':
		if (!ex) {
			PARSEERR;
		} else {
			char t[ULSTRLEN];

			ultostr(time(NULL), t);
			APPEND(strlen(t), t);
		}
		break;
	case 'p':
		{
		char **validdomains;
		int cnt;

		cnt = validate_domain(&validdomains);
		switch (cnt) {
		case 0:
			APPEND(7, "unknown");
			break;
		case -1:
			return -1;
		case -2:
			return SPF_TEMP_ERROR;
		case -3:
			return SPF_HARD_ERROR;
		default:
			{
			int k = spf_appendmakro(res, l, validdomains[0],
						strlen(validdomains[0]), num, r, delim);
			while (cnt > 0)
				free(validdomains[--cnt]);
			free(validdomains);
			if (k)
				return -1;
			}
		}
		break;
		}
	case 'r':
		if (!ex) {
			PARSEERR;
		}
		if (spf_appendmakro(res, l, heloname.s, heloname.len, num, r, delim))
			return -1;
		break;
	case 'v':
		if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
			if (spf_appendmakro(res, l, "in-addr", 7, num, r, (delim & 0x3)))
				return -1;
		} else {
			APPEND(3, "ip6");
		}
		break;
	case 'h':
		if (spf_appendmakro(res, l, HELOSTR, HELOLEN, num, r, delim))
			return -1;
		break;
	default:
		APPEND(7, "unknown");
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
#define PARSEERR	{free(res); return SPF_FAIL_MALF;}


/**
 * expand a SPF makro
 *
 * @param token the token to parse
 * @param domain the current domain string
 * @param ex if this is an exp string
 * @param result the resulting string is stored here
 * @return if makro is valid or not
 * @retval 0 makro is valid, result is set
 * @retval -1 internal error (ENOMEM)
 * @retval SPF_FAIL_MALF syntax error
 *
 * not static, is called from targets/testspf.c
 */
int
spf_makro(const char *token, const char *domain, int ex, char **result)
{
	char *res = NULL;
	const char *p;
	unsigned int l;
	size_t toklen = 0;

	if (ex == 1) {
		toklen = strlen(token);
	} else {
		p = token;
		while ((*p != '\0') && !WSPACE(*p) && (*p != '/')) {
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

		if (l != 0) {
			res = malloc(l);
			if (!res) {
				return -1;
			}
			memcpy(res, token, l);
		}
		do {
			int z;

			switch (*++p) {
			case '-':
				APPEND(3, "%20");
				p++;
				break;
			case '_':
				APPEND(1, " ");
				p++;
				break;
			case '%':
				APPEND(1, "%");
				p++;
				break;
			case '{':
				z = spf_makroletter(++p, domain, ex, &res, &l);
				if (z == -1) {
					return z;
				} else if (z == -SPF_FAIL_MALF) {
					return SPF_FAIL_MALF;
				} else if (!z || (*(p + z) != '}')) {
					PARSEERR;
				}
				p += z + 1;
				break;
			default:
				free(res);
				return SPF_FAIL_MALF;
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
 * @brief parse the domainspec
 *
 * @param domain the current domain string
 * @param token pointer to the string after the token
 * @param domainspec here the expanded domain string is stored (memory will be malloced)
 * @param ip4cidr the length of the IPv4 net (parsed if present in token, -1 if none given)
 * @param ip6cidr same for IPv6 net length
 * @returns if domainspec is valid or not
 * @retval -1 error (ENOMEM)
 * @retval SPF_FAIL_MALF domainspec is syntactically invalid
 * @retval 0 everything is fine, domainspec is set
 */
static int
spf_domainspec(const char *domain, const char *token, char **domainspec, int *ip4cidr, int *ip6cidr)
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
		const char *t = token;
		const char *tokenend = NULL;

		while (*t && !WSPACE(*t) && (*t != '/')) {
			if (*t < 0)
				return SPF_FAIL_MALF;

			switch (i) {
			case SPF_MAKRO_NONE:
				if (*t == '%') {
					// never used: i = SPF_MAKRO_PERCENT;
					t++;
					/* fallthrough */
				} else {
					if ((*t < 0x21) || (*t > 0x7e))
						return SPF_FAIL_MALF;
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
					// never used: i = SPF_MAKRO_BRACE;
					t++;
					break;
				default:
					return SPF_FAIL_MALF;
				}
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
					// never used: i = SPF_MAKRO_LETTER;
					t++;
					break;
				default:
					return SPF_FAIL_MALF;
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
					tokenend = t;
					t++;
					continue;
				default:
					return SPF_FAIL_MALF;
				}
			}
		}

		if (i != SPF_MAKRO_NONE)
			return SPF_FAIL_MALF;

		/* domainspec must end in toplabel or macro-expand */
		if ((tokenend == NULL) || (t != tokenend + 1)) {
			const char *dot = t - 1;
			const char *last = t - 1;
			const char *tmp;
			int hasalpha = 0;

			/* ignore one trailing dot */
			if (*dot == '.') {
				dot--;
				last--;
			}

			while ((dot >= token) && (*dot != '.'))
				dot--;

			/* domainspec may not be only toplabel */
			if (*dot != '.')
				return SPF_FAIL_MALF;

			/* toplabel may not be empty */
			if (dot + 1 >= last)
				return SPF_FAIL_MALF;

			/* toplabel must begin and end with alphanum,
			 * enforce C locale here */
			if (!isalnum(*(dot + 1)))
				return SPF_FAIL_MALF;
			if (!isalnum(*last))
				return SPF_FAIL_MALF;

			/* toplabel mal only be alphanum or '-' and
			 * must have at least one ALPHA */
			for (tmp = dot + 1; tmp <= last; tmp++) {
				hasalpha |= isalpha(*tmp);
				if (!isalnum(*tmp) && (*tmp != '-'))
					return SPF_FAIL_MALF;
			}

			if (!hasalpha)
				return SPF_FAIL_MALF;
		}

		if ((i = spf_makro(token, domain, 0, domainspec))) {
			return i;
		}
		token = t;
	}
/* check if there is a cidr length given */
	if (*token == '/') {
		const char *c = token + 1;

		if (*c != '/') {
			char *cend;
			if ((*c == '\0') || WSPACE(*c)) {
				free(*domainspec);
				return SPF_FAIL_MALF;
			}
			*ip4cidr = strtol(c, &cend, 10);
			if ((*ip4cidr > 32) || (!WSPACE(*cend) && (*cend != '/') && (*cend != '\0'))) {
				free(*domainspec);
				return SPF_FAIL_MALF;
			}
			c = cend;
		} else {
			c--;
		}
		if (*c++ != '/') {
			*ip6cidr = -1;
		} else {
			char *cend;
			if (*c++ != '/') {
				free(*domainspec);
				return SPF_FAIL_MALF;
			}
			if ((*c == '\0') || WSPACE(*c)) {
				free(*domainspec);
				return SPF_FAIL_MALF;
			}
			*ip6cidr = strtol(c, &cend, 10);
			if ((*ip6cidr > 128) || !(WSPACE(*cend) || (*cend == '\0'))) {
				free(*domainspec);
				return SPF_FAIL_MALF;
			}
		}
	}
	return 0;
}

/**
 * @brief check if a domainspec is present
 * @param token the token to check
 * @returns if domainspec is present
 * @retval 0 no domainspec present
 * @retval 1 domainspec is present
 * @retval -SPF_FAIL_MALF invalid characters detected
 *
 * This does not check the domainspec itself, it only checks if one is given.
 */
static int
may_have_domainspec(const char *token)
{
	if (*token == '\0')
		return 0;

	if (WSPACE(*token))
		return 0;

	if (*token == ':') {
		token++;
		if ((*token == '\0') || WSPACE(*token))
			return SPF_FAIL_MALF;
		return 1;
	}

	/* Strictly speaking this is no domainspec, but the spf_domainspec()
	 * function will care for this, too. */
	if (*token == '/')
		return 1;

	return SPF_FAIL_MALF;
}

/* the SPF routines
 *
 * return values:
 *  SPF_NONE: no match
 *  SPF_PASS: match
 *  SPF_FAIL_MALF: parse error
 * -1: error (ENOMEM)
 */
static int
spfmx(const char *domain, const char *token)
{
	int ip6l = -1;
	int ip4l = -1;
	int i;
	struct ips *mx;
	char *domainspec = NULL;

	switch (may_have_domainspec(token)) {
	case 0:
		break;
	case 1:
		if (*token == ':')
			token++;
		i = spf_domainspec(domain, token, &domainspec, &ip4l, &ip6l);
		if (i != 0)
			return i;
		break;
	default:
		return SPF_FAIL_MALF;
	}

	if (ip4l < 0)
		ip4l = 32;
	if (ip6l < 0)
		ip6l = 128;

	if (domainspec) {
		i = ask_dnsmx(domainspec, &mx);
		free(domainspec);
	} else {
		i = ask_dnsmx(domain, &mx);
	}
	switch (i) {
	case 1:
		return SPF_NONE;
	case DNS_ERROR_TEMP:
		return SPF_TEMP_ERROR;
	case DNS_ERROR_PERM:
		return SPF_HARD_ERROR;
	case DNS_ERROR_LOCAL:
		return -1;
	}
	if (!mx)
		return SPF_NONE;
	/* Don't use the implicit MX for this. There are either all MX records
	 * implicit or none so we only have to look at the first one */
	assert(mx->addr == &mx->ad);
	assert(mx->count == 1);
	if (mx->priority >= MX_PRIORITY_IMPLICIT) {
		freeips(mx);
		return SPF_NONE;
	}
	if (IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip)) {
		struct ips *cur;
		unsigned short s;

		FOREACH_STRUCT_IPS(cur, s, mx) {
			assert(cur->addr == &cur->ad);
			assert(cur->count == 1);
			assert(s == 0);
			if (IN6_IS_ADDR_V4MAPPED(cur->addr + s) &&
					ip4_matchnet(&xmitstat.sremoteip,
							(struct in_addr *) &(cur->addr[s].s6_addr32[3]), ip4l)) {
				freeips(mx);
				return SPF_PASS;
			}
		}
#ifndef IPV4ONLY
	} else {
		struct ips *cur;
		unsigned short s;

		FOREACH_STRUCT_IPS(cur, s, mx) {
			assert(cur->addr == &cur->ad);
			assert(cur->count == 1);
			assert(s == 0);
			if (ip6_matchnet(&xmitstat.sremoteip, cur->addr + s, ip6l)) {
				freeips(mx);
				return SPF_PASS;
			}
		}
#endif /* IPV4ONLY */
	}
	freeips(mx);
	return SPF_NONE;
}

static int
spfa(const char *domain, const char *token)
{
	int ip6l = -1;
	int ip4l = -1;
	int i, j;
	int r = 0;
	struct in6_addr *ip;
	char *domainspec = NULL;
	const int v4 = IN6_IS_ADDR_V4MAPPED(&xmitstat.sremoteip);
	const char *lookup;

	switch (may_have_domainspec(token)) {
	case 0:
		break;
	case 1:
		if (*token == ':')
			token++;
		i = spf_domainspec(domain, token, &domainspec, &ip4l, &ip6l);
		if (i != 0)
			return i;
		break;
	default:
		return SPF_FAIL_MALF;
	}

	if (ip4l < 0) {
		ip4l = 32;
	}
	if (ip6l < 0) {
		ip6l = 128;
	}
	if (domainspec)
		lookup = domainspec;
	else
		lookup = domain;

	if (v4)
		i = ask_dnsa(lookup, &ip);
	else
		i = ask_dnsaaaa(lookup, &ip);

	free(domainspec);

	switch (i) {
	case 0:
		return SPF_NONE;
	case DNS_ERROR_TEMP:
		return SPF_TEMP_ERROR;
	case DNS_ERROR_LOCAL:
		return -1;
	default:
		if (i < 0)
			return SPF_HARD_ERROR;
	}

	r = SPF_NONE;
	for (j = 0; j < i; j++) {
		int match = 0;
		if (v4) {
			if (IN6_IS_ADDR_V4MAPPED(ip + j))
				match = ip4_matchnet(&xmitstat.sremoteip, (struct in_addr *)&(ip[j].s6_addr32[3]), ip4l);
		} else {
			if (!IN6_IS_ADDR_V4MAPPED(ip + j))
				match = ip6_matchnet(&xmitstat.sremoteip, ip + j, ip6l);
		}

		if (match) {
			r = SPF_PASS;
			break;
		}
	}
	free(ip);

	return r;
}

static int
spfexists(const char *domain, const char *token)
{
	int ip6l, ip4l, i, r = 0;
	char *domainspec;

	if ( (i = spf_domainspec(domain, token, &domainspec, &ip4l, &ip6l)) ) {
		return i;
	}
	if ((ip4l > 0) || (ip6l > 0) || !domainspec) {
		free(domainspec);
		return SPF_FAIL_MALF;
	}
	i = ask_dnsa(domainspec, NULL);
	free(domainspec);

	switch (i) {
	case 0:
		r = SPF_NONE;
		break;
	case DNS_ERROR_TEMP:
		r = SPF_TEMP_ERROR;
		break;
	case DNS_ERROR_LOCAL:
		r = -1;
		break;
	default:
		if (i < 0)
			r = SPF_HARD_ERROR;
		else
			r = SPF_PASS;
	}
	return r;
}

static int
spfptr(const char *domain, const char *token)
{
	int i, r = 0;
	char *domainspec = NULL;
	char **validdomains = NULL;
	const char *checkdom;

	switch (may_have_domainspec(token)) {
	case 0:
		break;
	case 1: {
		int ip4l, ip6l;

		if (*token == ':')
			token++;

		i = spf_domainspec(domain, token, &domainspec, &ip4l, &ip6l);
		if (i != 0)
			return i;
		if ((ip4l >= 0) || (ip6l >= 0)) {
			free(domainspec);
			return SPF_FAIL_MALF;
		}
		break;
		}
	default:
		return SPF_FAIL_MALF;
	}

	if (!xmitstat.remotehost.len) {
		free(domainspec);
		return SPF_NONE;
	}

	i = validate_domain(&validdomains);
	switch (i) {
	case 0:
		free(domainspec);
		return SPF_NONE;
	case -1:
		r = -1;
		break;
	case -2:
		r = SPF_TEMP_ERROR;
		break;
	case -3:
		r = SPF_HARD_ERROR;
		break;
	}

	assert(i > 0);

	if (domainspec) {
		checkdom = domainspec;
	} else {
		checkdom = domain;
	}

	const size_t dslen = strlen(checkdom);
	int j;

	for (j = 0; j < i; j++) {
		const size_t dlen = strlen(validdomains[j]);

		if (dlen < dslen) {
			continue;
		} else if (dlen == dslen) {
			if (strcmp(validdomains[j], checkdom) == 0) {
				r = SPF_PASS;
				break;
			}
		} else if (validdomains[j][dlen - dslen - 1] == '.') {
			/* This mechanism matches if the <target-name> is
				* either an ancestor of a validated domain name or
				* if the <target-name> and a validated domain name
				* are the same. */
			if (strcmp(validdomains[j] + dlen - dslen, checkdom) == 0) {
				r = SPF_PASS;
				break;
			}
		}
	}

	while (i > 0) {
		free(validdomains[--i]);
	}
	free(domainspec);
	free(validdomains);

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
		return SPF_FAIL_MALF;

	if (*sl == '/') {
		char *q;

		u = strtoul(sl + 1, &q, 10);
		if ((u < 8) || (u > 32) || (!WSPACE(*q) && (*q != '\0')))
			return SPF_FAIL_MALF;
	} else if (WSPACE(*sl) || !*sl) {
		u = 32;
	} else {
		return SPF_FAIL_MALF;
	}

	memset(ip4buf, 0, sizeof(ip4buf));
	memcpy(ip4buf, domain, ip4len);

	if (!inet_pton(AF_INET, ip4buf, &net))
		return SPF_FAIL_MALF;

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
		return SPF_FAIL_MALF;

	if (*sl == '/') {
		char *endp;
		u = strtoul(sl + 1, &endp, 10);
		if ((u < 8) || (u > 128) || (!WSPACE(*endp) && (*endp != '\0')))
			return SPF_FAIL_MALF;
	} else if (WSPACE(*sl) || !*sl) {
		u = 128;
	} else {
		return SPF_FAIL_MALF;
	}

	memset(ip6buf, 0, sizeof(ip6buf));
	memcpy(ip6buf, domain, ip6len);

	if (!inet_pton(AF_INET6, ip6buf, &net))
		return SPF_FAIL_MALF;

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

	/* Either spf_domainspec() is called before or it is checked to not
	 * contain only dots. */
	assert(len != 0);

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
 * @brief check if the token matches the given mechanism
 * @param token current token to match
 * @param mechanism the mechanism string to match
 * @param delimiters the delimiters that may be present after the token
 * @returns length of the matched mechanism on success
 * @retval 0 mechanism did not match
 */
static size_t
match_mechanism(const char *token, const char *mechanism, const char *delimiters)
{
	const size_t mechlen = strlen(mechanism);
	const char * const nextchar = token + mechlen;
	unsigned int i = 0;

	if (strncasecmp(token, mechanism, mechlen) != 0)
		return 0;

	if (WSPACE(*nextchar))
		return mechlen;

	if (*nextchar == '\0')
		return mechlen;

	while (delimiters[i] != '\0') {
		if (*nextchar == delimiters[i])
			return mechlen;
		i++;
	}

	return 0;
}

/**
 * check if the given token is a valid SPF modifier-name
 *
 * @param token the token to parse
 * @return the length of the modifier-name, i.e. the position of the terminating '='
 * @retval 0 the given token is no valid modifier-name
 */
static size_t
spf_modifier_name(const char *token)
{
	size_t res = 0;

	if (!*token)
		return 0;

	/* modifier name is ALPHA *( ALPHA / DIGIT / "-" / "_" / "." ), i.e.
		* ([a-zA-Z][a-zA-Z0-9-_\.]*) */
	if (!(((*token >= 'a') && (*token <= 'z')) ||
			((*token >= 'A') && (*token <= 'Z'))))
		return 0;

	res++;

	while (token[res] && !WSPACE(token[res])) {
		if (token[res] == '=')
			return res;

		if (((*token >= 'a') && (*token <= 'z')) ||
				((*token >= 'A') && (*token <= 'Z')) ||
				((*token >= '0') && (*token <= '9')) ||
				(*token == '_') ||
				(*token == '-') ||
				(*token == '.')) {
			res++;
		} else {
			break;
		}
	}

	return 0;
}

/**
 * write the bad token to the SPF explanation record
 *
 * @param token the current token string
 */
static void
record_bad_token(const char *token)
{
	/* This is an invalid token. Go back to the last whitespace
	 * and copy that to spfexp so it can be recorded in the
	 * Received-SPF line if the user still accepts the mail. We
	 * know there is at least one whitespace after the v=spf1
	 * token. Then go back until the next whitespace or to the
	 * end, replace any unsafe char by '%' */

	const char *tokenend = token;

	while (!WSPACE(*(token - 1)))
		token--;

	while (!WSPACE(*tokenend) && (*tokenend != '\0'))
		tokenend++;

	xmitstat.spfexp = malloc(tokenend - token + 1);
	/* it's just logging, ignore if it fails */
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
		return SPF_FAIL_MALF;

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
		case ENOENT:
			return SPF_NONE;
		case ETIMEDOUT:
		case EIO:
		case ECONNREFUSED:
		case EAGAIN:
			return SPF_TEMP_ERROR;
		case EINVAL:
			return SPF_HARD_ERROR;
		case ENOMEM:
		default:
			return -1;
		}
	}
	if (!txt)
		return SPF_NONE;
	token = txt;
	while ((token = strstr(token, "v=spf1"))) {
		if (valid) {
			free(txt);
			return SPF_FAIL_MALF;
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
		size_t mechlen;

		while (WSPACE(*token)) {
			token++;
		}
		if (!*token) {
			mechanism = "default";
			break;
		}
		switch(*token) {
		case '-':
			token++; prefix = SPF_FAIL_PERM;
			break;
		case '~':
			token++; prefix = SPF_SOFTFAIL;
			break;
		case '+':
			token++; prefix = SPF_PASS;
			break;
		case '?':
			token++; prefix = SPF_NEUTRAL;
			break;
		default:
			if (((*token >= 'a') && (*token <= 'z')) ||
					((*token >= 'A') && (*token <= 'Z'))) {
				prefix = SPF_PASS;
			} else {
				free(txt);
				return SPF_FAIL_MALF;
			}
		}
		if ( (mechlen = match_mechanism(token, "mx", ":/")) != 0) {
			token += mechlen;

			result = spfmx(domain, token);
			mechanism = "MX";
		} else if ( (mechlen = match_mechanism(token, "ptr", ":/")) != 0) {
			token += mechlen;

			result = spfptr(domain, token);
			mechanism = "PTR";
		} else if ( (mechlen = match_mechanism(token, "exists", ":")) != 0) {
			token += mechlen;

			if (*token++ == ':') {
				result = spfexists(domain, token);
				mechanism = "exists";
			} else {
				result = SPF_FAIL_MALF;
			}
		} else if ( (mechlen = match_mechanism(token, "all", "")) != 0) {
			token += mechlen;
			result = SPF_PASS;
			mechanism = "all";
		} else if ( (mechlen = match_mechanism(token, "a", ":/")) != 0) {
			token += mechlen;

			result = spfa(domain, token);
			mechanism = "A";
		} else if ( (mechlen = match_mechanism(token, "ip4", ":/")) != 0) {
			token += mechlen;

			if (*token++ == ':') {
				result = spfip4(token);
				mechanism = "IP4";
			} else {
				result = SPF_FAIL_MALF;
			}
		} else if ( (mechlen = match_mechanism(token, "ip6", ":/")) != 0) {
			token += mechlen;

			if (*token++ == ':') {
				result = spfip6(token);
				mechanism = "IP6";
			} else {
				result = SPF_FAIL_MALF;
			}
		} else if ( (mechlen = match_mechanism(token, "include", ":")) != 0) {
			token += mechlen;

			if (may_have_domainspec(token) == 1) {
				char *n = NULL;
				int ip4l, ip6l;

				result = spf_domainspec(domain, token + 1, &n, &ip4l, &ip6l);
				if (result == 0) {
					if ((ip4l >= 0) || (ip6l >= 0)) {
						result = SPF_FAIL_MALF;
					} else {
						result = spflookup(n, rec + 1);
					}
					free(n);
				}
			} else {
				result = SPF_FAIL_MALF;
			}

			switch (result) {
			case SPF_NONE:
				result = SPF_PASS;
				prefix = SPF_FAIL_MALF;
				break;
			case SPF_TEMP_ERROR:
			case SPF_FAIL_MALF:
				prefix = result;
				result = SPF_PASS;
				break;
			case SPF_PASS:
			case -1:
				break;
			default:
				result = SPF_NONE;
			}

			mechanism = "include";
		} else {
			/* assume this is a modifier (defined in RfC 4408, section 4.6.1) */
			size_t eq = spf_modifier_name(token);

			if (eq == 0) {
				prefix = SPF_FAIL_MALF;
				result = SPF_PASS;
				break;
			} else {
				char *mres = NULL;

				result = spf_makro(token + eq + 1, domain, 0, &mres);
				if (result == SPF_FAIL_MALF) {
					prefix = SPF_FAIL_MALF;
					result = SPF_PASS;

					record_bad_token(token);
					break;
				} else if (result == 0) {
					/* we don't need it here */
					free(mres);
					if (!redirect && (strncasecmp(token, "redirect", strlen("redirect")) == 0))
						redirect = token + eq + 1;
					token += eq + 1;
				} else {
					break;
				}
			}
		}
/* skip to the end of this token */
		while (*token && !WSPACE(*token)) {
			token++;
		}
		if ((result == SPF_TEMP_ERROR) || (result == SPF_HARD_ERROR) || (result == SPF_FAIL_MALF)) {
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

				switch (spf_makro(ex + 4, domain, 0, &target)) {
				case 0:
					{
					size_t dlen = strlen(target);
					while ((dlen > 0) && (target[dlen - 1] == '.')) {
						target[--dlen] = '\0';
					}
					if (dlen > 0) {
						char *exp;
						if (txtlookup(&exp, target) == 0) {
							/* if this fails the standard answer will be used */
							(void)spf_makro(exp, domain, 1, &xmitstat.spfexp);
							free(exp);
						}
					}
					free(target);
					break;
					}
				case SPF_FAIL_MALF:
					prefix = SPF_FAIL_MALF;
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
				result = SPF_FAIL_MALF;
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
