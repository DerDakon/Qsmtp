/** @file client.c
 * @brief SMTP client code to parse server replies
 */

#include <qremote/client.h>
#include <qremote/qremote.h>
#include <qremote/statuscodes.h>
#include <netio.h>
#include <qdns.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * print remote host information to buffer
 *
 * @param m list of MX entries, entry with priority 65538 is active
 */
void
getrhost(const struct ips *m)
{
	int r;

	free(partner_fqdn);
	free(rhost);

	/* find active mx */
	while (m->priority != 65538)
		m = m->next;

	r = ask_dnsname(&m->addr, &partner_fqdn);
	if (r <= 0) {
		if ((r == 0) || (errno != ENOMEM)) {
			rhost = malloc(INET6_ADDRSTRLEN + 2);
		}
		if (errno == ENOMEM)
			err_mem(1);

		rhost[0] = '[';
		rhostlen = 1;
		partner_fqdn = NULL;
	} else {
		rhostlen = strlen(partner_fqdn);
		rhost = malloc(rhostlen + INET6_ADDRSTRLEN + 3);

		if (rhost == NULL)
			err_mem(1);

		memcpy(rhost, partner_fqdn, rhostlen);
		rhost[rhostlen++] = ' ';
		rhost[rhostlen++] = '[';
	}
	/* there can't be any errors here ;) */
	(void) inet_ntop(AF_INET6, &m->addr, rhost + rhostlen, INET6_ADDRSTRLEN);
	rhostlen = strlen(rhost);
	rhost[rhostlen++] = ']';
	rhost[rhostlen] = '\0';
}

/**
 * check the reply of the server
 *
 * @param status status codes to print or NULL if not to
 * @param pre text to write to stdout before server reply if mask matches
 * @param mask bitmask for pre: 1: 2xx, 2: 4xx, 4: 5xx
 * @return the SMTP result code
 *
 * status must be at least 3 bytes long but only the first 3 will have any effect. The first
 * one is the status code writen on success (server response is 2xx), the second on on temporary
 * error (4xx) and the third on permanent error (5xx). If no status code should be written status
 * must be set to NULL. If the first character in status is ' ' no message will be printed for
 * success messages.
 */
int
checkreply(const char *status, const char **pre, const int mask)
{
	int res;
	int ignore = 0;

	res = netget();
	if (status) {
		int m;

		if ((res >= SUCCESS_MINIMUM_STATUS) && (res <= SUCCESS_MAXIMUM_STATUS)) {
			if (status[0] == ' ') {
				ignore = 1;
			} else {
				write(1, status, 1);
			}
			m = 1;
		} else if ((res >= TEMP_MINIMUM_STATUS) && (res <= TEMP_MAXIMUM_STATUS)) {
			write(1, status + 1, 1);
			m = 2;
		} else {
			write(1, status + 2, 1);
			m = 4;
		}
		if (!ignore) {
			if (pre && (m & mask)) {
				int i = 0;

				while (pre[i]) {
					write(1, pre[i], strlen(pre[i]));
					i++;
				}
			}
			write(1, linein, linelen);
		}
	}
	while (linein[3] == '-') {
		/* ignore the SMTP code sent here, if it's different from the one before the server is broken */
		(void) netget();
		if (status && !ignore) {
			write(1, linein, linelen);
			write(1, "\n", 1);
		}
	}

	if (status && !ignore)
		write(1, "", 1);
	/* this allows us to check for 2xx with (x < 300) later */
	if (res < 200)
		res = 599;
	return res;
}
