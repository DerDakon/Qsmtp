/** \file addrsyntax.c
 \brief check syntax of email addresses and SMTP helos
 */

#include <qsmtpd/addrparse.h>

#include <qdns.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

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
 * @retval 2 address contains \@domain
 * @retval 3 address is a full email address
 * @retval 4 address is a full email address with IPv4 or IPv6 address literal
 */
static int __attribute__ ((pure)) __attribute__ ((nonnull (1)))
parseaddr(const char *addr)
{
	const char *at = strchr(addr, '@');

	if (!at)
		return 1 - domainvalid(addr);
	/* RfC says localpart should not be longer than 64 bytes
	 * but one should be prepared to see longer ones. Since e.g.
	 * ezmlm creates localparts with more characters we don't set
	 * any limit on the length here. */

	/* paranoid ones would check for (at == addr+i) here */
	if (parselocalpart(addr) < 0)
		return 0;

	if (*addr == '@')
		return domainvalid(addr + 1) ? 0 : 2;
	if (*(at + 1) == '[') {
		const char *cl = strchr(at + 2, ']');
		size_t addrlen;

		if (!cl || *(cl + 1))
			return 0;
		if (!strncmp(at + 2, "IPv6:", 5)) {
			struct in6_addr ip6;
			char ipbuf[INET6_ADDRSTRLEN];

			addrlen = cl - at - 7;
			if (addrlen >= INET6_ADDRSTRLEN)
				return 0;
			memcpy(ipbuf, at + 7, addrlen);
			ipbuf[addrlen] = '\0';
			return (inet_pton(AF_INET6, ipbuf, &ip6) <= 0) ? 0 : 4;
		} else {
			char ipbuf[INET_ADDRSTRLEN];
			struct in_addr ip4;

			addrlen = cl - at - 2;
			if (addrlen >= INET_ADDRSTRLEN)
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
 * @return if address valid
 * @retval 0 address is valid
 * @retval 1 address is invalid
 *
 * This is just !parseaddr(addr). This allows this to be used as callback.
 */
int
checkaddr(const char *const addr)
{
	return !parseaddr(addr);
}

/**
 * check if the given string is a valid addr-spec
 *
 * @param addr string to check
 * @return if string is valid addrspec
 * @retval 0 string is invalid
 * @retval 1 string is valid
 */
int
addrspec_valid(const char * const addr)
{
	return (parseaddr(addr) >= 3);
}

/**
 * @brief check an email address for syntax errors
 *
 * @param in address to parse
 * @param flags
 *              @arg @c 0: mail from checks,
 *              @arg @c 1: rcpt to checks (e.g. source route is allowed),
 *              @arg @c 2: checks for badmailfrom/goodmailfrom lists
 * @param addr struct string to contain the address (memory will be malloced)
 * @param more here starts the data behind the first '>' behind the first '<' (or NULL if none)
 * @return >0 on success
 * @retval 1 address is empty (only possible if flags is 0)
 * @retval 3 address is a full email address
 * @retval 4 address is a full email address with IPv4 or IPv6 address literal
 * @retval 0 in is invalid
 * @retval -1 an error occured (e.g. ENOMEM)
 */
int
addrsyntax(char *in, const int flags, string *addr, char **more)
{
	char *f, *l;			/* pointer to the begin and end of the mail address
					 * in "in" (without source route and other crap) */
	char *t;			/* temporary storage */
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

	size_t len = l - f;		/* length of the recip address */
	/* check if something follow the '>' */
	if (more && *(l + 1)) {
		*more = l + 1;
	}
	/* empty address is only allowed in MAIL FROM */
	if (!flags && !len) {
		if (addr)
			STREMPTY(*addr);
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
		if (newstr(addr, len + 1))
			return -1;

		strncpy(addr->s, f, len);
		addr->s[--addr->len] = '\0';
		while (len > 0) {
			len--;
			if ((addr->s[len] >= 'A') && (addr->s[len] <= 'Z'))
				addr->s[len] = addr->s[len] + ('a' - 'A');
		}
	}

	return x;
}
