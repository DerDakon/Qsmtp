#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <syslog.h>
#include <resolv.h>
#include <unistd.h>
#include <errno.h>
#include "antispam.h"
#include "log.h"
#include "dns.h"

/**
 * nibbletohex - take a nibble and output it as hex to a buffer, followed by '.'
 *
 * dest: pointer where the output should go to
 * n: the input value. Must really be a nibble, anything else makes strange output
 */
static inline void
nibbletohex(char *dest, const char n)
{
	*dest++ = ((n > 9) ? 'a' - 10 : '0') + n;
	*dest = '.';
}

/**
 * check_rbl - do a rbl lookup for remoteip
 *
 * remoteip: IPv6 address of the remote host
 * rbls: a NULL terminated array of rbls
 *
 * returns: on match the index of the first match is returned
 *          -1 if not listed or error (if not listed errno is set to 0)
 */
int
check_rbl(const struct in6_addr *remoteip, const char **rbls, char **txt)
{
	char lookup[256];
	unsigned int l;
	int i = 0;
	int again = 0;	/* if this is set at least one rbl lookup failed with temp error */

	if (IN6_IS_ADDR_V4MAPPED(remoteip->s6_addr)) {
		struct in_addr r;

		r.s_addr = (remoteip->s6_addr[12] << 24) + (remoteip->s6_addr[13] << 16) +
					(remoteip->s6_addr[14] << 8) + remoteip->s6_addr[15];
		inet_ntop(AF_INET, &r, lookup, sizeof(lookup));
		l = strlen(lookup);
		lookup[l++] = '.';
	} else {
		int k;
		for (k = 15; k >= 0; k--) {
			nibbletohex(lookup + k * 4,     (remoteip->s6_addr[k] & 0x0f));
			nibbletohex(lookup + k * 4 + 2, (remoteip->s6_addr[k] & 0xf0) >> 4);
		}
		l = 64;
	}
	while (rbls[i]) {
		const char *logmsg[] = {"name of rbl too long: \"", NULL, "\"", NULL};
		int j;

		if (strlen(rbls[i]) >= sizeof(lookup) - l) {
			logmsg[1] = rbls[i];
			log_writen(LOG_ERR, logmsg);
		} else {
			char *r;
			unsigned int ul;

			strcpy(lookup + l, rbls[i]);
			j = dnsip4(&r, &ul, lookup);
			if ( (j < 0) && (errno == ENOMEM) )
				return j;
			if (!j) {
				int k;

				free(r);
				k = dnstxt(txt, lookup);
				/* if there is any error here we just write the generic message to the client
				 * so that's no real problem for us */
				if (k)
					*txt = NULL;
				return i;
			} else if (j == 2) {
				/* This lookup failed with temporary error. We continue and check the other RBLs first, if
				 * one matches we can block permanently, only if no other matches we block mail with 4xx */
				again = 1;
			}
		}
		i++;
	}
	errno = again ? EAGAIN : 0;
	return -1;
}

static unsigned int tarpitcount = 0;	/* number of extra seconds from tarpit */

/**
 * tarpit - delay the next reply to the client
 *
 * This should be used in all places where the client seems to be a spammer. This will
 * delay him so he can't send so much spams.
 */
inline void
tarpit(void)
{
	sleep(5 +  tarpitcount);
	/* maximum sleep time is 4 minutes */
	if (tarpitcount < 235)
		tarpitcount++;
}

/**
 * check_ip4 - check an IPv4 mapped IPv6 address against a local blocklist
 *
 * @remoteip: the IP to check
 * @buf: buffer of local blocklist, each entry is 5 bytes long
 * @len: length of the buffer
 *
 * returns: 1 if match, 0 if not, -1 if data malformed
 *
 * IP entries in the buffer must be network byte order
 */
int
check_ip4(const struct in6_addr *remoteip, const unsigned char *buf, const unsigned int len)
{
	unsigned int i;

	if (len % 5)
		return -1;
	for (i = 0; i < len; i += 5) {
		struct in_addr mask;
		/* cc shut up: we know what we are doing here */
		const struct in_addr *ip = (struct in_addr *) buf;

		if ((*(buf + 4) < 8) || (*(buf + 4) > 32))
			return -1;
		/* constuct a bit mask out of the net length.
		 * remoteip and ip are network byte order, it's easier
		 * to convert mask to network byte order than both
		 * to host order. It's ugly, isn't it? */
		mask.s_addr = htonl(-1 - ((1 << (32 - *(buf + 4))) - 1));

		if ((remoteip->s6_addr32[3] & mask.s_addr) == ip->s_addr) {
			return 1;
		}
		buf += 5;
	}
	return 0;
}

/**
 * check_ip6 - check an IPv6 address against a local blocklist
 *
 * @remoteip: the IP to check
 * @buf: buffer of local blocklist, each entry is ? bytes long
 * @len: length of the buffer
 *
 * returns: 1 if match, 0 if not, -1 if data malformed
 */
int
check_ip6(const struct in6_addr *remoteip, const unsigned char *buf, const unsigned int len)
{
	unsigned int i;

	if (len % 9)
		return -1;
	for (i = 0; i < len; i += 9) {
		const struct in6_addr *ip = (struct in6_addr *) buf;
		struct in6_addr mask;
		int i, flag = 4;

		if ((*(buf + 9) < 8) || (*(buf + 4) > 128))
			return -1;
		/* construct a bit mask out of the net length */
		if (*(buf + 9) < 32) {
			mask.s6_addr32[0] = 0xffffffff;
			mask.s6_addr32[1] = 0xffffffff;
			mask.s6_addr32[2] = 0xffffffff;
			/* remoteip and ip are network byte order, it's easier
			 * to convert mask to network byte order than both
			 * to host order. We do it at this point because we only
			 * need to change one word per mask, the other 3 will stay
			 * the same before and after htonl() */
			mask.s6_addr32[3] = htonl(-1 - (1 << ((32 - *(buf + 4)) - 1)));
		} else {
			mask.s6_addr32[3] = 0;
			if (*(buf + 9) < 64) {
				mask.s6_addr32[0] = 0xffffffff;
				mask.s6_addr32[1] = 0xffffffff;
				mask.s6_addr32[2] = htonl(-1 - (1 << ((64 - *(buf + 4)) - 1)));
			} else {
				mask.s6_addr32[2] = 0;
				if (*(buf + 9) < 96) {
					mask.s6_addr32[0] = 0xffffffff;
					mask.s6_addr32[1] = htonl(-1 - (1 << ((96 - *(buf + 4)) - 1)));
				} else {
					mask.s6_addr32[0] = htonl(-1 - (1 << ((128 - *(buf + 4)) - 1)));
					mask.s6_addr32[1] = 0;
				}
			}
		}

#if __WORDSIZE == 64
		/* compare 8 bytes at once */
		flag = 2;
		if ((*((unsigned long long *) remoteip) & ((unsigned long long) mask)) == *((unsigned long long *) ip))
			flag--;
		if ((((unsigned long long *) remoteip)[1] & ((unsigned long long *) mask)[1]) == ((unsigned long long) ip)[1])
			flag--;
#else
		for (i = 3; i >= 0; i--)
			if ((remoteip->s6_addr32[i] & mask.s6_addr32[i]) == ip->s6_addr32[i])
				flag--;
#endif
		if (!flag)
			return 1;
		buf += 9;
	}
	return 0;
}

/**
 * domainmatch - check if a given host name matches against domain list
 *
 * @fqdn: hostname to check
 * @list: list of domains and hosts to check against, NULL terminated
 *
 * returns: 1 on match, 0 otherwise
 *
 * -if list is NULL terminated and every list[x] and fqdn are '\0' terminated there can't be any errors
 * -list is always freed
 */
int
domainmatch(const char *fqdn, const unsigned int len, const char **list)
{
	unsigned int i = 0;
	int rc = 0;

	while (list[i]) {
		if (*list[i] == '.') {
			unsigned int k = strlen(list[i]);

			if (k < len) {
				/* compare a[i] with the last k bytes of xmitstat.mailfrom.s */
				if (!strcasecmp(fqdn + (len - k), list[i])) {
					rc = 1;
					break;
				}
			}
		} else if (!strcasecmp(list[i], fqdn)) {
			rc = 1;
			break;
		}

		i++;
	}	
	free(list);
	return rc;
}
