/** \file addrsyntax.c
 \brief check syntax of email addresses and SMTP helos
 */
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "sstring.h"
#include "qdns.h"
#include "qsmtpd.h"

/**
 * check syntax correctness of local part
 *
 * @param addr address to check
 * @return -1 on syntax error, length of localpart otherwise. If no '@' in addr, length of addr
 * @retval -1 syntax error in localpart
 */
static int __attribute__ ((pure)) __attribute__ ((nonnull (1)))
parselocalpart(const char *const addr)
{
	const char *t = addr;
	int quoted = 0;

	/* RfC 2821, section 4.1.2
	 * Systems MUST NOT define mailboxes in such a way as to require the use
	 * in SMTP of non-ASCII characters (octets with the high order bit set
	 * to one) or ASCII "control characters" (decimal value 0-31 and 127).
	 * These characters MUST NOT be used in MAIL or RCPT commands or other
	 * commands that require mailbox names.
	 *
	 * RfC 2822, section 3.2.4
	 * Any character except controls, SP and specials.
	 */
	while (*t && (*t != '@')) {
		if (*t == '"') {
			quoted = 1 - quoted;
		} else if (!quoted) {
			/* these characters are allowed without quoting */
			if (!(((*t >= 'a') && (*t <= 'z')) || ((*t >= 'A') && (*t <= 'Z')) || (*t == '.') ||
						((*t >= '0') && (*t <= '9')) || (*t == '!') || ((*t >= '#') && (*t <= '\'')) ||
						(*t == '*') || (*t == '+') || (*t == '-') || (*t == '/') || (*t == '=') ||
						(*t == '?') || ((*t >= '^') && (*t <= '`')) || ((*t >= '{') && (*t <= '~')))) {
				return -1;
			}
		} else {
			/* check for everything outside range of allowed characters in quoted string */
			if (!(((*t >= 35) && (*t <= 91)) || (*t >= 93) || ((*t >= 1) && (*t <= 8)) || (*t == 11) ||
						(*t == 12) || ((*t >= 14) && (*t <= 31)))) {
				if (*t == '\\') {
					/* '\\' may mask only '"' or '\\'. Skip this second character, else error */
					if ((*(t + 1) == '"') || (*(t + 1) == '\\')) {
						t++;
					} else {
						return -1;
					}
				} else {
					return -1;
				}
			}
		}
		t++;
	}
	if (quoted)
		return -1;
	return t - addr;
}

/**
 * check type and correctness of mail address
 *
 * @param addr address to check
 * @return status code indicating what type of address was found
 * @retval 0 address invalid
 * @retval 1 address only contains a domain name
 * @retval 2 address contains @domain
 * @retval 3 address is a full email address
 * @retval 4 address is a full email address with IPv4 or IPv6 address literal
 */
static int __attribute__ ((pure)) __attribute__ ((nonnull (1)))
parseaddr(const char *addr)
{
	const char *at = strchr(addr, '@');

	if (!at)
		return 1 - domainvalid(addr);
	/* localpart too long */
	if ((at - addr) > 64)
		return 0;
	/* paranoid ones would check for (at == addr+i) here */
	if (parselocalpart(addr) < 0)
		return 0;

	/* domain name too long */
	if (strlen(at + 1) > 64)
		return 0;
	if (*addr == '@')
		return domainvalid(addr + 1) ? 0 : 2;
	if (*(at + 1) == '[') {
		const char *cl = strchr(at + 2, ']');
		size_t addrlen;

		if (!cl || *(cl + 1))
			return 0;
		if (!strncmp(cl + 1, "IPv6:", 5)) {
			struct in6_addr ip6;
			char ipbuf[INET6_ADDRSTRLEN];

			addrlen = cl - at - 7;
			if (addrlen > INET6_ADDRSTRLEN)
				return 0;
			memcpy(ipbuf, at + 7, addrlen);
			ipbuf[addrlen] = '\0';
			return (inet_pton(AF_INET6, ipbuf, &ip6) <= 0) ? 0 : 4;
		} else {
			char ipbuf[INET_ADDRSTRLEN];
			struct in_addr ip4;

			addrlen = cl - at - 2;
			if (addrlen > INET_ADDRSTRLEN)
				return 0;
			memcpy(ipbuf, at + 2, addrlen);
			ipbuf[addrlen] = '\0';
			return (inet_pton(AF_INET, ipbuf, &ip4) <= 0) ? 0 : 4;
		}
	} else {
		return domainvalid(at + 1) ? 0 : 3;
	}
}

/**
 * check an email address for validity, use as loadlistfd callback
 *
 * @param addr the address to check
 * @return 0 if address valid
 */
int
checkaddr(const char *const addr)
{
	return !parseaddr(addr);
}

/**
 * check an email address for syntax errors
 *
 * @param in address to parse
 * @param flags 1: rcpt to checks (e.g. source route is allowed), 0: mail from checks,
 *              2: checks for badmailfrom/goodmailfrom lists
 * @param addr struct string to contain the address (memory will be malloced)
 * @param more here starts the data behind the first '>' behind the first '<' (or NULL if none)
 * @return >0 on success
 * @retval 0 in is invalid
 * @retval -1 an error occured (e.g. ENOMEM)
 */
int
addrsyntax(char *in, const int flags, string *addr, char **more)
{
	char *f, *l;			/* pointer to the begin and end of the mail address
					 * in "in" (without source route and other crap) */
	char *t;			/* temporary storage */
	int len;			/* length of the recip address */
	int x = 1;

	f = in;
	if ((flags == 1) && (*f == '@')) {
		/* strip source route
		 * source route has the form
		 * "{@f.q.dn,}*@fq.dn:"
		 * we don't care if the host does not exist, we just look for syntax errors
		 */
		while ( (t = strchr(f, ',')) ) {
			*t++ = '\0';
			if (domainvalid(f + 1))
				return 0;
			f = t;
			if (*f != '@')
				return 0;
		}
		t = strchr(f, ':');
		if (!t)
			return 0;
		*t++ = '\0';
		if (domainvalid(f + 1))
			return 0;
		/* RfC 2821, Section 4.5.3.1: The maximum total length of a reverse-path or forward-path
		 * is 256 characters (including the punctuation and element separators). */
		if ((t - in) > 256)
			return 0;
		f = t;
	}
	l = strchr(f, '>');
	if (!l)
		return 0;

	len = l - f;
	/* check if something follow the '>' */
	if (more && *(l + 1)) {
		*more = l + 1;
	}
	/* empty address is only allowed in MAIL FROM */
	if (!flags && !len) {
		if (addr) {
			addr->s = NULL;
			addr->len = 0;
		}
		return 1;
	}
	*l = '\0'; /* from now on the complete mail address is just *f */

	/* postmaster is allowed without '@', all other valid addresses must have
	 * localpart + '@' + domain */
	if ((flags != 1) || strcasecmp(f, "postmaster")) {
		x = parseaddr(f);
		if (x < 3)
			return 0;
	}

	if (addr) {
		addr->s = malloc(len + 1);
		if (!addr->s)
			return -1;
	
		strncpy(addr->s, f, len);
		addr->s[len] = '\0';
		addr->len = len;
		while (len > 0) {
			len--;
			if ((addr->s[len] >= 'A') && (addr->s[len] <= 'Z'))
				addr->s[len] = addr->s[len] + ('a' - 'A');
		}
	}

	return x;
}

/**
 * check if the argument given to HELO/EHLO is syntactically correct
 *
 * @param helo helo to check
 * @return 0 on successful call, -1 on error
 * @retval 0 check was completed (xmitstat.helostatus was updated)
 * @retval -1 an error occured (usually ENOMEM)
 *
 * the status of the helo string ist stored in xmitstat.helostatus
 */
int
helovalid(const char *helo)
{
	char *s;
	int rc;

	xmitstat.helostatus = 0;
	if (xmitstat.helostr.s)
		free(xmitstat.helostr.s);

	/* We have the length of both strings anyway so we might be able to see
	 * the difference without looking at every single character in them */
	if (xmitstat.remotehost.len == strlen(helo)) {
		/* HELO is identical to reverse lookup: valid */
		if (!strcasecmp(helo, xmitstat.remotehost.s)) {
			STREMPTY(xmitstat.helostr);
			return 0;
		}
	}

	if ( (rc = newstr(&xmitstat.helostr, strlen(helo) + 1)) )
		return rc;
	/* +5-4=+1: also copy the '\0' to the new string */
	memcpy(xmitstat.helostr.s, helo, xmitstat.helostr.len--);

	if (!strcasecmp(helo, heloname.s)) {
		xmitstat.helostatus = 0;
		return 0;
	}

	s = getenv("TCPLOCALIP");
	if (s) {
		unsigned int sl = strlen(s);

		/* clear sign of spammers */
		if (!strcmp(helo, s)) {
			xmitstat.helostatus = 5;
			return 0;
		}
		/* I've never seen this happen, but it's also broken. It is valid if connection comes from
		 * localhost and process can't figure out hostname, but why not use qmail-inject or sendmail then? */
		if ((*helo == '[') && (helo[xmitstat.helostr.len - 1] == ']') && !strncmp(helo + 1, s, sl)) {
			xmitstat.helostatus = 2;
			return 0;
		}
	}
	/* check if the argument is a valid domain name */
	if (!domainvalid(helo)) {
		xmitstat.helostatus = 0;
		return 0;
	}

	xmitstat.helostatus = 3;
	/* it's not: it must be a IP literal enclosed in [] */
	if ((*helo != '[') || (!(s = strchr(xmitstat.helostr.s + 1, ']'))))
		return 0;

	/* there must not be any characters after the ']' */
	if (!*(s+1)) {
		struct in_addr ia;

		/* make the address string end where the ']' is so that inet_pton works */
		*s = '\0';
		if (inet_pton(AF_INET, xmitstat.helostr.s + 1, &ia))
			xmitstat.helostatus = 0;
		*s = ']';
	}
	return 0;
}
