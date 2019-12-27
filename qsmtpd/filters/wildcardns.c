#include <qsmtpd/userfilters.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "control.h"
#include <qsmtpd/qsmtpd.h>

/** \struct dns_wc
 * \brief list entry of a wildcard nameserver for a top level domain
 */
#define MAXTLDLEN 6
struct dns_wc {
		struct in6_addr ip;	/**< IP address of nameserver */
		char tld[MAXTLDLEN + 1];	/**< Top Level Domain ip serves for */
		size_t len;		/**< length of tld */
};

static int
validns(const char *inp)
{
	unsigned int i = 0;
	struct in6_addr ip;

	while (((inp[i] >= 'a') && (inp[i] <= 'z')) || ((inp[i] >= 'A') && (inp[i] <= 'Z')))
		i++;
	if ((inp[i] != '_') || (i > MAXTLDLEN))
		return 1;
	i++;

	return inet_pton(AF_INET6, inp + i, &ip) > 0 ? 0 : 1;
}

/**
 * @brief load the wildcardns entries
 * @return entry count of wcs
 */
static int
loadjokers(struct dns_wc **wcs)
{
	int i, cnt;
	char **inputs;

	*wcs = NULL;

	if (loadlistfd(openat(controldir_fd, "wildcardns", O_RDONLY | O_CLOEXEC), &inputs, &validns))
		return 0;

	if (inputs == NULL)
		return 0;

	for (cnt = 1; inputs[cnt]; cnt++)
		;

	*wcs = calloc(cnt, sizeof(**wcs));
	if (*wcs == NULL) {
		free(inputs);
		return -1;
	}

	cnt = 0;

	for (i = 0; inputs[i]; i++) {
		struct dns_wc *t = (*wcs) + cnt;
		size_t j = 0;

		while (inputs[i][j] != '_') {
			t->tld[j] = inputs[i][j];
			j++;
		}
		t->tld[j] = '\0';
		t->len = j++;

		/* this was checked before, so it will work */
		inet_pton(AF_INET6, inputs[i] + j, &t->ip);
		cnt++;
	}
	free(inputs);

	return cnt;
}

enum filter_result
cb_wildcardns(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	struct ips *thismx;
	unsigned short s;
	struct dns_wc *dns_wildcards;
	int cnt;
	int match;

	if (xmitstat.frommx == NULL)
		return FILTER_PASSED;

	/* if there is a syntax error in the file it's the users fault and this mail will be accepted */
	if (getsettingglobal(ds, "block_wildcardns", t) <= 0)
		return FILTER_PASSED;

	/* the only case this returns an error is ENOMEM */
	cnt = loadjokers(&dns_wildcards);
	if (cnt < 0)
		return FILTER_ERROR;

	FOREACH_STRUCT_IPS(thismx, s, xmitstat.frommx) {
		int i;

		match = 0;

		for (i = 0; i < cnt; i++) {
			if (xmitstat.mailfrom.len < dns_wildcards[i].len + 1)
				continue;

			/* check if top level domain of sender address matches this entry */
			if ((xmitstat.mailfrom.s[xmitstat.mailfrom.len - dns_wildcards[i].len - 1] != '.') ||
					strcasecmp(xmitstat.mailfrom.s + xmitstat.mailfrom.len - dns_wildcards[i].len, dns_wildcards[i].tld))
				continue;

			if (IN6_ARE_ADDR_EQUAL(thismx->addr + s, &(dns_wildcards[i].ip))) {
				match = 1;
				break;
			}
		}

		if (!match)
			break;
	}

	free(dns_wildcards);

	if (!match)
		return FILTER_PASSED;
	*logmsg = "MX is wildcard NS entry";
	return FILTER_DENIED_UNSPECIFIC;
}
