#include <qsmtpd/userfilters.h>

#include <netinet/in.h>
#include <arpa/inet.h>
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
		struct dns_wc *next;	/**< next item in list */
};

static int __attribute__ ((pure))
validns(const char *inp)
{
	int i = 0;

	while (((inp[i] >= 'a') && (inp[i] <= 'z')) || ((inp[i] >= 'A') && (inp[i] <= 'Z')))
		i++;
	if ((inp[i] != '_') || (i > MAXTLDLEN))
		return 1;
	i++;
	while (((inp[i] >= 'a') && (inp[i] <= 'f')) || ((inp[i] >= 'A') && (inp[i] <= 'F')) ||
				((inp[i] >= '0') && (inp[i] <= '9')) || (inp[i] == ':') || (inp[i] == '.'))
		i++;
	return inp[i];
}

static int
loadjokers(struct dns_wc **wcs)
{
	int i;
	struct dns_wc **this = wcs;
	char **inputs;

	if (loadlistfd(openat(controldir_fd, "wildcardns", O_RDONLY | O_CLOEXEC), &inputs, &validns))
		return 0;

	if (inputs == NULL)
		return 0;

	for (i = 0; inputs[i]; i++) {
		struct dns_wc t;
		size_t j = 0;

		t.next = NULL;

		while (inputs[i][j] != '_') {
			t.tld[j] = inputs[i][j];
			j++;
		}
		t.tld[j] = '\0';
		t.len = j++;
		if (inet_pton(AF_INET6, inputs[i] + j, &t.ip) <= 0)
			continue;
		*this = malloc(sizeof(**this));
		if (!*this) {
			while (*wcs) {
				*this = (*wcs)->next;
				free(*wcs);
				*wcs = *this;
			}
			free(inputs);
			return -1;
		}
		**this = t;
		this = &((*this)->next);
	}
	free(inputs);
	return 0;
}

enum filter_result
cb_wildcardns(const struct userconf *ds, const char **logmsg, enum config_domain *t)
{
	struct ips *thismx;
	unsigned short s;
	struct dns_wc *dns_wildcards;
	int match = 0;

	/* we can't check the from domain on a bounce message */
	if (!xmitstat.mailfrom.len || !xmitstat.frommx)
		return FILTER_PASSED;

	/* if there is a syntax error in the file it's the users fault and this mail will be accepted */
	if (getsettingglobal(ds, "block_wildcardns", t) <= 0)
		return FILTER_PASSED;

	if (loadjokers(&dns_wildcards))
		return FILTER_ERROR;

	FOREACH_STRUCT_IPS(thismx, s, xmitstat.frommx) {
		struct dns_wc *this;

		for (this = dns_wildcards; this != NULL; this = this->next) {
			if (xmitstat.mailfrom.len < this->len + 1)
				continue;

			/* check if top level domain of sender address matches this entry */
			if ((xmitstat.mailfrom.s[xmitstat.mailfrom.len - this->len - 1] != '.') ||
					strcasecmp(xmitstat.mailfrom.s + xmitstat.mailfrom.len - this->len, this->tld))
				continue;

			if (IN6_ARE_ADDR_EQUAL(thismx->addr + s, &this->ip)) {
				match = 1;
				break;
			}
		}

		if (!match)
			break;
	}

	while (dns_wildcards != NULL) {
		struct dns_wc *next = dns_wildcards->next;
		free(dns_wildcards);
		dns_wildcards = next;
	}

	if (!match)
		return FILTER_PASSED;
	*logmsg = "MX is wildcard NS entry";
	return FILTER_DENIED_UNSPECIFIC;
}
