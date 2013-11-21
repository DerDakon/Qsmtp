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
#include <mmap.h>

static const char *tags[] = {
	"host",
	"port",
	NULL
};

static int
hascolon(const char *s)
{
	char *colon = strchr(s, ':');

	if (!colon)
		return 1;
	return (*(colon + 1) == ':');
}

static unsigned int tagmask;

static int
validroute(const char *s)
{
	const char *last = strchr(s, '=');
	size_t len;
	unsigned int i;

	if (last == NULL)
		return 1;

	if (last == s)
		return 1;

	len = last - s;

	for (i = 0; tags[i] != NULL; i++) {
		if (strlen(tags[i]) != len)
			continue;

		if (strncmp(tags[i], s, len) == 0) {
			const unsigned int tag = 1 << i;

			/* duplicate tag is error */
			if (tagmask & tag)
				return 1;

			tagmask |= tag;
			return 0;
		}
	}

	return 1;
}

/**
 * @brief get static route for domain
 *
 * @param remhost target to look up
 * @param reml strlen(remhost)
 * @param targetport port on the remote host to connect to
 * @returns MX list if route present
 * @retval NULL a runtime error occurred while reading the control file, errno is set
 *
 * If control/smtproutes contains a syntax error the program is terminated.
 * On runtime error (out of memory) NULL is returned and errno is set.
 */
struct ips *
smtproute(const char *remhost, const size_t reml, unsigned int *targetport)
{
	char **smtproutes, *smtproutbuf;
	struct ips *mx = NULL;
	char fn[320]; /* length of domain + control/smtproutes.d */
	const char dirname[] = "control/smtproutes.d/";
	const char *curpart = remhost;
	/* check if the dir exists at all to avoid probing for every
	 * subdomain if the dir does not exist. */
	const int dirfd = open(dirname, O_RDONLY);

	memcpy(fn, dirname, strlen(dirname));
	strcpy(fn + strlen(dirname), remhost);

	*targetport = 25;

	if (dirfd >= 0) {
		close(dirfd);

		while (1) {
			char *buf, **array;
			int fd = open(fn, O_RDONLY);
			unsigned int i = 0;
			const char *val;
			const char *target;

			if (fd < 0) {
				if (errno != ENOENT) {
					const char *errmsg[] = {
							"error opening smtproute file for domain ",
							remhost, NULL};
					err_confn(errmsg, NULL);
				}
				if (curpart == NULL) {
					break;
				} else {
					const char *dot = strchr(curpart, '.');

					if (dot == NULL) {
						strcpy(fn + strlen(dirname), "default");
						curpart = NULL;
					} else {
						fn[strlen(dirname)] = '*';
						strcpy(fn + strlen(dirname) + 1, dot);

						curpart = dot + 1;
					}
					continue;
				}
			}

			tagmask = 0;

			/* no error, and host must be present */
			if ((loadlistfd(fd, &buf, &array, validroute) != 0) || ((tagmask & 1) == 0)) {
				const char *errmsg[] = {
						"error opening smtproute file for domain ",
						remhost, NULL};
				err_confn(errmsg, NULL);
			}

			/* find host */
			while (strncmp(array[i], tags[0], strlen(tags[0])) != 0)
				i++;

			val = array[i] + strlen(tags[0]) + 1;

			target = val;
			if (ask_dnsaaaa(val, &mx)) {
				const char *logmsg[] = {"cannot find IP address for static route \"",
						target, "\" given as target for \"",
						remhost, "\"", NULL};

				free(array);
				err_confn(logmsg, buf);
			} else {
				struct ips *m = mx;
				while (m) {
					m->priority = 0;
					m = m->next;
				}
			}

			if (tagmask & 2) {
				i = 0;

				while (strncmp(array[i], tags[1], strlen(tags[1])) != 0)
					i++;

				val = array[i] + strlen(tags[1]) + 1;

				char *more;
				
				/* overwrite the colon ending the hostname so the code
				* below will not take this as part of the host name */
				*targetport = strtoul(val, &more, 10);
				if ((*more != '\0') || (*targetport >= 65536) || (*targetport == 0)) {
					const char *logmsg[] = {"invalid port number '", val,
							"' given for \"",
							target, "\" given as target for \"",
							remhost, "\"", NULL};
	
					free(array);
					/* smtproutbuf not freed here as "port" still references it */
					err_confn(logmsg, buf);
				}
				
			} else {
				*targetport = 25;
			}

			free(array);
			free(buf);

			return mx;
		}
	}

	if (!loadlistfd(open("control/smtproutes", O_RDONLY), &smtproutbuf, &smtproutes, hascolon) && smtproutbuf) {
		unsigned int k = 0;

		while (smtproutes[k]) {
			char *target = strchr(smtproutes[k], ':');
			*target++ = '\0';

			if (!*(smtproutes[k]) || matchdomain(remhost, reml, smtproutes[k])) {
				char *port;

				port = strchr(target, ':');
				if (port) {
					char *more;

					/* overwrite the colon ending the hostname so the code
					 * below will not take this as part of the host name */
					*port++ = '\0';
					*targetport = strtoul(port, &more, 10);
					if (*more || (*targetport >= 65536) || (*targetport == 0)) {
						const char *logmsg[] = {"invalid port number '", port,
									"' given for \"",
									target, "\" given as target for \"",
									remhost, "\"", NULL};

						free(smtproutes);
						/* smtproutbuf not freed here as "port" still references it */
						err_confn(logmsg, smtproutbuf);
					}
				} else {
					*targetport = 25;
				}
				if (ask_dnsaaaa(target, &mx)) {
					const char *logmsg[] = {"cannot find IP address for static route \"",
									target, "\" given as target for \"",
									remhost, "\"", NULL};

					free(smtproutes);
					/* smtproutbuf not freed here as "port" still references it */
					err_confn(logmsg, smtproutbuf);
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
