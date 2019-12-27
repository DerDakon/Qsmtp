/** @file client.c
 * @brief SMTP client code to parse server replies
 */

#include <qremote/client.h>

#include <netio.h>
#include <qdns.h>
#include <qremote/qremote.h>
#include <qremote/statuscodes.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief print remote host information to buffer
 * @param m the currently active MX entry
 * @param s index of the currently active IP address
 */
void
getrhost(const struct ips *m, const unsigned short idx)
{
	free(partner_fqdn);
	free(rhost);

	if (m->name == NULL) {
		partner_fqdn = NULL;
		rhost = malloc(INET6_ADDRSTRLEN + 2);
		if (rhost == NULL)
			err_mem(1);

		rhostlen = 0;
	} else {
		partner_fqdn = strdup(m->name);
		rhostlen = strlen(m->name);
		rhost = malloc(rhostlen + INET6_ADDRSTRLEN + 3);

		if ((rhost == NULL) || (partner_fqdn == NULL)) {
			free(rhost);
			free(partner_fqdn);
			err_mem(1);
		}

		memcpy(rhost, partner_fqdn, rhostlen);
		rhost[rhostlen++] = ' ';
	}
	rhost[rhostlen++] = '[';
	/* there can't be any errors here ;) */
	(void) inet_ntop(AF_INET6, m->addr + idx, rhost + rhostlen, INET6_ADDRSTRLEN);
	rhostlen = strlen(rhost);
	rhost[rhostlen++] = ']';
	rhost[rhostlen] = '\0';
}

/**
 * check the reply of the server
 *
 * @param status status codes to print or NULL if not to
 * @param pre text to write to stdout before server reply if mask matches
 * @param mask bitmask for pre: 1: 2xx, 2: 4xx, 4: 5xx, 8: do not write network message for 2xx
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
	int ignore = (status == NULL);

	int res = netget(1);
	if (status) {
		unsigned int m;	// mask bit

		if ((res >= SUCCESS_MINIMUM_STATUS) && (res <= SUCCESS_MAXIMUM_STATUS)) {
			if (status[0] == ' ')
				ignore = 1;
			else
				m = 0;
		} else if ((res >= TEMP_MINIMUM_STATUS) && (res <= TEMP_MAXIMUM_STATUS)) {
			m = 1;
		} else {
			m = 2;
		}
		if (!ignore) {
			write_status_raw(status + m, 1);

			if (pre && ((1 << m) & mask)) {
				unsigned int pcount = 0;
				while (pre[pcount])
					pcount++;
				write_status_raw_m(pre, pcount);
			}

			if ((m == 0) && (mask & 8)) {
				write_status_raw("", 1);
				ignore = 1;
			}
		}
	}

	/* consume multiline reply */
	while (linein.s[3] == '-') {
		/* send out the last (buffered) line */
		if (!ignore) {
			/* Put the newline into linein to avoid a second write just for that.
			 * Since linein is always 0-terminated there is enough space to hold
			 * that character, and the contents of linein are overwritten by the
			 * following call to netget() anyway. */
			linein.s[linein.len] = '\n';
			write_status_raw(linein.s, linein.len + 1);
		}
		/* ignore the SMTP code sent here, if it's different from the one before the server is broken */
		(void) netget(1);
	}

	if (!ignore)
		write_status(linein.s);
	/* this allows us to check for 2xx with (x < 300) later */
	if (res < 200)
		res = 599;
	return res;
}
