#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "sstring.h"
#include "dns.h"
#include "qsmtpd.h"

/**
 * parseaddr - check type and correctness of mail address
 *
 * @addr: address to check
 *
 * returns: 0: address invalid
 *          1: address only contains a domain name
 *          2: address contains @domain
 *          3: address is a full email address
 */
static int
parseaddr(const char *addr)
{
	const char *t, *at = strchr(addr, '@');

	t = addr;
	/* RfC 2821, section 4.1.2
	 * Systems MUST NOT define mailboxes in such a way as to require the use
	 * in SMTP of non-ASCII characters (octets with the high order bit set
	 * to one) or ASCII "control characters" (decimal value 0-31 and 127).
	 * These characters MUST NOT be used in MAIL or RCPT commands or other
	 * commands that require mailbox names.
	 *
	 * '/' is illegal because it can be misused to check for the existence of
	 * arbitrary files. The other one are just because I don't like them *eg* */
	while (t < addr) {
		const char *badchars = "\\|'`/";
		const unsigned int numbc = strlen(badchars);
		unsigned int i;

		if ((*t + 1) < 32)
			return 1;
		/* if we don't do this someone may be able to check if
		 * USERNAME/DIRECTORY exists if localpart is "username/directory"
		 * Also a user with '\' or '|' and so on in it's name will not exist here
		 */
		for (i = 0; i < numbc; i++) {
			if (*t == badchars[i])
				return 0;
		}

		*t++;
	}
	if (!at)
		return 1 - domainvalid(addr, 0);

	/* domain name too long */
	if (strlen(at + 1) > 255)
		return 0;
	/* localpart too long */
	if ((at - addr) > 65)
		return 0;
	if (*addr == '@')
		return domainvalid(addr + 1, 0) ? 0 : 2;
	return domainvalid(at + 1, 0) ? 0 : 3;
}

/**
 * checkaddr - check an email address for validity, use as loadlistfd callback
 *
 * @addr: the address to check
 * @f: passed as "flags" to addrsyntax
 */
int
checkaddr(const char *addr, const int f __attribute__ ((unused)))
{
	return !parseaddr(addr);
}

/**
 * addrsyntax - check an email address for syntax errors
 *
 * @flags:   1: rcpt to checks (e.g. source route is allowed), 0: mail from checks,
 *           2: checks for badmailfrom/goodmailfrom lists
 * @addr:    struct string to contain the address (memory will be malloced)
 * @more:    here starts the data behind the first > behind the first < (or NULL if none)
 *
 * returns: 0 on success, -1 on error (e.g. ENOMEM), 1 if address is invalid
 */
int
addrsyntax(char *in, const int flags, string *addr, char **more)
{
	char *f, *l;			/* pointer to the begin and end of the mail address
					 * in "in" (without source route and other crap) */
	char *t;			/* temporary storage */
	int len;			/* length of the recip address */
	int x;

	f = strchr(in, '<');
	if (!f)
		return 1;
	if (flags == 1) {
		/* strip source route
		 * source route has the form
		 * "{@f.q.dn,}*@fq.dn:"
		 * we don't care if the host does not exist, we just look for syntax errors
		 */
		if (*(f+1) == '@') {
			f++;
			while ( ( t = strchr(f,',') ) ) {
				*t++ = '\0';
				if (domainvalid(f + 1,0))
					return 1;
				f = t;
				if (*f != '@')
					return 1;
			}
			t = strchr(f, ':');
			if (!t)
				return 1;
			*t++ = '\0';
			if (domainvalid(f + 1,0))
				return 1;
			/* RfC 2821, Section 4.5.3.1: The maximum total length of a reverse-path or forward-path
			 * is 256 characters (including the punctuation and element separators). */
			if ((t - in + 5) > 256)
				return 1;
			f = t;
		}
	}
	l = strchr(f, '>');
	if (!l)
		return 1;

	len = l - f - 1;
	/* empty address is only allowed in MAIL FROM */
	if (!flags && !len) {
		if (addr) {
			addr->s = NULL;
			addr->len = 0;
		}
		return 0;
	}
	/* check if something follow the '>' */
	if (more) {
		*more = (l + 1);
		if (!**more)
			*more = NULL;
	}
	*l = '\0'; /* from now on the complete mail address is just *(f+1) */

	/* postmaster is allowed without '@', all other valid addresses must have
	 * localpart + '@' + domain */
	if ((flags != 1) || strcasecmp(f + 1, "postmaster")) {
		x = parseaddr(f);
		if (x < 3)
			return 1;
	}

	if (addr) {
		addr->s = malloc(len + 1);
		if (!addr->s) {
			return -1;
		}
	
		strncpy(addr->s, f + 1, len);
		addr->s[len] = '\0';
		addr->len = len;
	}

	return 0;
}

/**
 * helovalid - check if the argument given to HELO/EHLO is syntactically correct
 *
 * @helo: helo to check
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
	if (!domainvalid(helo, 0)) {
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
