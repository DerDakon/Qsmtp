#include <qsmtpd/userfilters.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "control.h"
#include <qsmtpd/qsmtpd.h>

static int __attribute__ ((pure))
validns(const char *inp)
{
	int i = 0;

	while (((inp[i] >= 'a') && (inp[i] <= 'z')) || ((inp[i] >= 'A') && (inp[i] <= 'Z')))
		i++;
	if ((inp[i] != '_') || (i > 6))
		return 1;
	i++;
	while (((inp[i] >= 'a') && (inp[i] <= 'f')) || ((inp[i] >= 'A') && (inp[i] <= 'F')) ||
				((inp[i] >= '0') && (inp[i] <= '9')) || (inp[i] == ':') || (inp[i] == '.'))
		i++;
	return inp[i];
}

/** \struct dns_wc
 * \brief list entry of a wildcard nameserver for a top level domain
 */
struct dns_wc {
		struct in6_addr ip;	/**< IP address of nameserver */
		char tld[7];		/**< Top Level Domain ip serves for */
		size_t len;		/**< length of tld */
		struct dns_wc *next;	/**< next item in list */
};

static int
loadjokers(struct dns_wc **wcs)
{
	int i;
	struct dns_wc **this = wcs;
	char **inputs;

	if (loadlistfd(open("control/wildcardns", O_RDONLY | O_CLOEXEC), &inputs, &validns))
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

static struct dns_wc *dns_wildcards;

int
cb_wildcardns(const struct userconf *ds, const char **logmsg, int *t)
{
	struct dns_wc *this;

	/* we can't check the from domain on a bounce message */
	if (!xmitstat.mailfrom.len || !xmitstat.frommx)
		return 0;

	/* if there is a syntax error in the file it's the users fault and this mail will be accepted */
	if (getsettingglobal(ds, "block_wildcardns", t) <= 0)
		return 0;

	if (!dns_wildcards)
		if (loadjokers(&dns_wildcards))
			return -1;

	this = dns_wildcards;
	while (this) {
		/* check if top level domain of sender address matches this entry */
		if ((xmitstat.mailfrom.s[xmitstat.mailfrom.len - this->len - 1] != '.') ||
				strcasecmp(xmitstat.mailfrom.s + xmitstat.mailfrom.len - this->len, this->tld)) {
			this = this->next;
			continue;
		}
		if (IN6_ARE_ADDR_EQUAL(&(xmitstat.frommx->addr), &(this->ip))) {
			*logmsg = "MX is wildcard NS entry";
			return 2;
		}
		this = this->next;
	}
	return 0;
}
