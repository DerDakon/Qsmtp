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
#include <qremote/qremote.h>
#include <mmap.h>

static const char *tags[] = {
	"relay",
	"port",
	NULL
};

/**
 * @brief check smtproutes entries for basic syntax errors
 * @return 0 if the line is valid, i.e. it contains exactly 1 or 2 colons
 */
static int
hascolon(const char *s)
{
	char *colon = strchr(s, ':');

	if (!colon)
		return 1;

	colon = strchr(colon + 1, ':');
	if (colon == NULL)
		return 0;

	colon++;

	while (*colon != '\0') {
		if ((*colon < '0') || (*colon > '9'))
			return 1;
		colon++;
	}

	return 0;
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

static const char *
tagvalue(char **lines, const unsigned int idx)
{
	unsigned int i = 0;

	while (strncmp(lines[i], tags[idx], strlen(tags[idx])) != 0)
		i++;
	
	return lines[i] + strlen(tags[idx]) + 1;
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
	char **smtproutes;
	struct ips *mx = NULL;
	char fn[320]; /* length of domain + control/smtproutes.d */
	const char dirname[] = "control/smtproutes.d/";
	const char *curpart = remhost;
	/* check if the dir exists at all to avoid probing for every
	 * subdomain if the dir does not exist. */
	const int dirfd = open(dirname, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	const size_t diroffs = 0;

	strcpy(fn + diroffs, remhost);

	*targetport = 25;

	if (dirfd >= 0) {
		while (1) {
			char **array;
			int fd = openat(dirfd, fn, O_RDONLY | O_CLOEXEC);
			const char *target = NULL;

			if (fd < 0) {
				if (errno != ENOENT) {
					const char *errmsg[] = {
							"error opening smtproute.d file for domain ",
							remhost, NULL};
					err_confn(errmsg, NULL);
				}
				if (curpart == NULL) {
					close(dirfd);
					break;
				} else {
					const char *dot = strchr(curpart, '.');

					if (dot == NULL) {
						strcpy(fn + diroffs, "default");
						curpart = NULL;
					} else {
						fn[diroffs] = '*';
						strcpy(fn + diroffs + 1, dot);

						curpart = dot + 1;
					}
					continue;
				}
			}

			tagmask = 0;

			/* no error */
			if (loadlistfd(fd, &array, validroute) != 0) {
				const char *errmsg[] = {
						"error loading smtproute.d file for domain ",
						remhost, NULL};
				err_confn(errmsg, NULL);
			}

			if (tagmask & 1) {
				/* find host */
				const char *val = tagvalue(array, 0);

				target = val;
				if (ask_dnsaaaa(val, &mx)) {
					const char *logmsg[] = {"cannot find IP address for static route \"",
							target, "\" given as target for \"",
							remhost, "\"", NULL};

					err_confn(logmsg, array);
				} else {
					struct ips *m = mx;
					while (m) {
						m->priority = 0;
						m = m->next;
					}
				}
			}

			if (tagmask & 2) {
				char *more;
				const char *val = tagvalue(array, 1);

				*targetport = strtoul(val, &more, 10);
				if ((*more != '\0') || (*targetport >= 65536) || (*targetport == 0)) {
					const char *logmsg[] = {"invalid port number '", val,
							"' given for \"",
							target ? target : "",
							"\" given as target for \"", remhost, "\"", NULL};

					freeips(mx);
					err_confn(logmsg, array);
				}
				
			} else {
				*targetport = 25;
			}

			free(array);

			close(dirfd);
			return mx;
		}
	}

	if ((loadlistfd(open("control/smtproutes", O_RDONLY | O_CLOEXEC), &smtproutes, hascolon) == 0) && (smtproutes != NULL)) {
		unsigned int k = 0;

		while (smtproutes[k]) {
			char *target = strchr(smtproutes[k], ':');
			*target++ = '\0';

			if (!*(smtproutes[k]) || matchdomain(remhost, reml, smtproutes[k])) {
				char *port;

				port = strchr(target, ':');
				if (port) {
					/* overwrite the colon ending the hostname so the code
					 * below will not take this as part of the host name */
					*port++ = '\0';
					*targetport = strtoul(port, NULL, 10);
					if ((*targetport >= 65536) || (*targetport == 0)) {
						const char *logmsg[] = {"invalid port number '", port,
									"' given for \"",
									target, "\" given as target for \"",
									remhost, "\"", NULL};

						err_confn(logmsg, smtproutes);
					}
				} else {
					*targetport = 25;
				}

				if (!*target) {
					/* do nothing, let the normal DNS search happen */
				} else if (ask_dnsaaaa(target, &mx)) {
					const char *logmsg[] = {"cannot find IP address for static route \"",
									target, "\" given as target for \"",
									remhost, "\"", NULL};

					err_confn(logmsg, smtproutes);
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
	}

	errno = 0;
	return mx;
}
