/** \file smtproutes.c
 \brief functions for handling of control/smtproutes
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <assert.h>
#include "qdns.h"
#include "control.h"
#include "match.h"
#include "log.h"
#include "qremote.h"

static int
hascolon(const char *s)
{
	char *colon = strchr(s, ':');

	if (!*colon)
		return 0;
	return (*(colon + 1) == ':');
}

/**
 * smtproute - get static route for domain
 * @remhost: target to look up
 * @reml: strlen(remhost)
 * @returns: MX list if route present, else NULL
 *
 * If control/smtproutes contains a syntax error the program is terminated.
 * On runtime error (out of memory) NULL is returned and errno is set.
 */
struct ips *
smtproute(const char *remhost, const size_t reml, unsigned int *targetport)
{
	char **smtproutes, *smtproutbuf;
	struct ips *mx = NULL;

	if (!loadlistfd(open("control/smtproutes", O_RDONLY), &smtproutbuf, &smtproutes, hascolon) && smtproutbuf) {
		char *target;
		unsigned int k = 0;

		while (smtproutes[k]) {
			target = strchr(smtproutes[k], ':');
			*target++ = '\0';

			if (!*(smtproutes[k]) || matchdomain(remhost, reml, smtproutes[k])) {
				char *port;

				port = strchr(target, ':');
				if (port) {
					char *more;

					*port++ = '\0';
					*targetport = strtoul(port, &more, 10);
					if (*more || (*targetport >= 65536)) {
						const char *logmsg[] = {"invalid port number given for \"",
									target, "\" given as target for \"",
									remhost, "\"", NULL};

						err_confn(logmsg);
					}
				}
				if (ask_dnsaaaa(target, &mx)) {
					const char *logmsg[] = {"cannot find IP address for static route \"",
									target, "\" given as target for \"",
									remhost, "\"", NULL};

					err_confn(logmsg);
				} else {
					struct ips *m = mx;
					while (m) {
						m->priority = 0;
						m = m->next;
					}
					break;
				}
			}
			k++;
		}
		free(smtproutes);
		free(smtproutbuf);
	}

	errno = 0;
	return mx;
}
