/** \file antispam.c
 \brief several helper functions for spam filters
 */
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "antispam.h"
#include "log.h"
#include "libowfatconn.h"
#include "qsmtpd.h"
#include "control.h"
#include "tls.h"
#include "match.h"
#include "netio.h"

/**
 * take a nibble and output it as hex to a buffer, followed by '.'
 *
 * @param dest pointer where the output should go to
 * @param n the input value. Must really be a nibble, anything else makes strange output
 */
static inline void
nibbletohex(char *dest, const char n)
{
	*dest++ = ((n > 9) ? 'a' - 10 : '0') + n;
	*dest = '.';
}

/**
 * print IPv6 address of remote host in dotted form in buffer
 *
 * @param buffer buffer to store result
 */
void
dotip6(char *buffer)
{
	int k;

	for (k = 15; k >= 0; k--) {
		nibbletohex(buffer + k * 4,     (xmitstat.sremoteip.s6_addr[k] & 0xf0) >> 4);
		nibbletohex(buffer + k * 4 + 2, (xmitstat.sremoteip.s6_addr[k] & 0x0f));
	}
}
/**
 * print client IPv4 address in reverse order into a given buffer
 *
 * @param buf buffer to write in (must have at least INET_ADDRSTRLEN (16) bytes)
 * @return length of string in buffer
 */
int
reverseip4(char *buf)
{
	struct in_addr r;

	r.s_addr = (xmitstat.sremoteip.s6_addr[12] << 24) + (xmitstat.sremoteip.s6_addr[13] << 16) +
			(xmitstat.sremoteip.s6_addr[14] << 8) + xmitstat.sremoteip.s6_addr[15];
	inet_ntop(AF_INET, &r, buf, INET_ADDRSTRLEN);
	return strlen(buf);
}

/**
 * do a rbl lookup for remoteip
 *
 * @param rbls a NULL terminated array of rbls
 * @param txt pointer to "char *" where the TXT record of the listing will be stored if !NULL
 * @return \arg \c index of first match
 *         \arg \c -1 if not listed or error (if not listed errno is set to 0)
 */
int
check_rbl(char *const *rbls, char **txt)
{
	char lookup[256];
	unsigned int l;
	int i = 0;
	int again = 0;	/* if this is set at least one rbl lookup failed with temp error */

	if (!rbls) {
		errno = 0;
		return -1;
	}

	if (xmitstat.ipv4conn) {
		l = reverseip4(lookup);
		lookup[l++] = '.';
	} else {
		dotip6(lookup);
		l = 64;
	}
	while (rbls[i]) {
		const char *logmsg[] = {"name of rbl too long: \"", NULL, "\"", NULL};
		int j;

		if (strlen(rbls[i]) >= sizeof(lookup) - l) {
			logmsg[1] = rbls[i];
			log_writen(LOG_ERR, logmsg);
		} else {
			struct ips *ip;

			strcpy(lookup + l, rbls[i]);
			j = ask_dnsa(lookup, &ip);
			if (j < 0) {
				return j;
			} else if (!j) {
				freeips(ip);

				/* if there is any error here we just write the generic message to the client
				 * so that's no real problem for us */
				dnstxt(txt, lookup);
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
 * delay the next reply to the client
 *
 * This should be used in all places where the client seems to be a spammer. This will
 * delay him so he can't send so much spams.
 *
 * tarpit does not sleep if there is input pending. If the client is using pipelining or (more likely) a worm or spambot
 * ignoring our replies we kick him earlier and save some traffic.
 */
void
tarpit(void)
{
	if (data_pending())
		return;
	if (ssl) {
		/* SSL encoding is too much overhead for worms and friends, so at the other side we can expect a real
		 * mail server. We just have to check here if there is data pending (he's using PIPELINING) or not. */
		sleep(5 + tarpitcount);
	} else {
		fd_set rfds;
		struct timeval tv = {
			.tv_sec = 5 + tarpitcount,
			.tv_usec = 0,
		};

		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		/* don't care about the return value here: if something goes wrong we will only not
		 * sleep long enough here. If something is really bad (ENOMEM or something) the error
		 * will happen again and will be caught at another place */
		select(1, &rfds, NULL, NULL, &tv);
	}

	/* maximum sleep time is 4 minutes */
	if (tarpitcount < 235)
		tarpitcount++;
}

/**
 * check an IPv4 mapped IPv6 address against a local blocklist
 *
 * @param buf buffer of local blocklist, each entry is 5 bytes long
 * @param len length of the buffer
 * @returns \arg \c 1 if match \arg \c 0 if no match \arg \c -1 if data malformed
 *
 * IP entries in the buffer must be network byte order
 */
static int
check_ip4(const unsigned char *buf, const unsigned int len)
{
	unsigned int i;

	if (len % 5)
		return -1;
	for (i = 0; i < len; i += 5) {
		/* cc shut up: we know what we are doing here */
		const struct in_addr *ip = (struct in_addr *) buf;

		if ((*(buf + 4) < 8) || (*(buf + 4) > 32))
			return -1;
		if (ip4_matchnet(&xmitstat.sremoteip, ip, *(buf + 4)))
			return 1;
		buf += 5;
	}
	return 0;
}

/**
 * check an IPv6 address against a local blocklist
 *
 * @param buf buffer of local blocklist, each entry is 9 bytes long
 * @param len length of the buffer
 * @return 1 if match, 0 if not, -1 if data malformed
 */
static int
check_ip6(const unsigned char *buf, const unsigned int len)
{
	unsigned int i;

	if (len % 17)
		return -1;
	for (i = 0; i < len; i += 17) {
		const struct in6_addr *ip = (struct in6_addr *) buf;

		if ((*(buf + 16) < 8) || (*(buf + 16) > 128))
			return -1;
		if (ip6_matchnet(&xmitstat.sremoteip, ip, *(buf + 16)))
			return 1;
		buf += 9;
	}
	return 0;
}

/**
 * check if a given host name matches against domain list
 *
 * @param fqdn hostname to check
 * @param len length of fqdn
 * @param list list of domains and hosts to check against, NULL terminated
 * @return 1 on match, 0 otherwise
 *
 * -if list is NULL terminated and every list[x] and fqdn are 0-terminated there can't be any errors
 * -list is always freed
 */
int
domainmatch(const char *fqdn, const unsigned int len, const char **list)
{
	unsigned int i = 0;
	int rc = 0;

	while (list[i]) {
		if (matchdomain(fqdn, len, list[i])) {
			rc = 1;
			break;
		}
		i++;
	}
	free(list);
	return rc;
}

/**
 * check if the remote host is listed in local IP map file given by fd
 *
 * @param fd file descriptor to file
 * @return \arg \c <0 on error \arg \c >0 on match \arg \c 0 otherwise
 */
int
lookupipbl(int fd)
{
	int i, rc;
	char *map;		/* map the file here */
	struct stat st;

	while (flock(fd,LOCK_SH)) {
		if (errno != EINTR) {
			log_write(LOG_WARNING, "cannot lock input file");
			errno = ENOLCK;	/* not the right error code, but good enough */
			return -1;
		}
	}
	if ( (i = fstat(fd, &st)) )
		return i;
	if (!st.st_size) {
		while ( (rc = close(fd)) ) {
			if (errno != EINTR)
				return rc;
		}
		return 0;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		int e = errno;

		while (close(fd)) {
			if (errno != EINTR)
				break;
		}
		errno = e;
		return -1;
	}

	if (xmitstat.ipv4conn) {
		rc = check_ip4(map, st.st_size);
	} else {
		rc = check_ip6(map, st.st_size);
	}
	munmap(map, st.st_size);
	while ((i = close(fd))) {
		if (errno != EINTR) {
			break;
		}
	}
	return i ? i : rc;
}
