/** \file smtproutes.c
 \brief functions for handling of control/smtproutes
 */

#include <qremote/qremote.h>

#include <control.h>
#include <diropen.h>
#include <log.h>
#include <match.h>
#include <mmap.h>
#include <qdns.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

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
 * @brief parse the parts of an smtproute
 * @param mx MX result list is stored here
 * @param remhost original remote host
 * @param targetport targetport will be stored here
 * @param buf additional buffer, will be freed in case of fatal error
 * @param host host name of smtproute or NULL
 * @param port port string of smtproute of NULL
 * @retval 0 values were successfully parsed
 * @retval <0 error code during setup
 *
 * The function will abort the program if a parse error occurs.
 */
static int __attribute__ ((nonnull(1, 2, 3, 4)))
parse_route_params(struct ips **mx, const char *remhost, unsigned int *targetport, void *buf, const char *host, const char *port)
{
	if (host != NULL) {
		struct in6_addr *a;
		int cnt = ask_dnsaaaa(host, &a);
		if (cnt <= 0) {
			const char *logmsg[] = {"cannot find IP address for static route \"",
					host, "\" given as target for \"",
					remhost, "\"", NULL};

			err_confn(logmsg, buf);
		} else {
			int is_ip;

			*mx = in6_to_ips(a, cnt, 0);

			if (*mx == NULL)
				return -ENOMEM;

			/* decide if the name of the MX should be copied: copy it
				* it it doesn't look like an IPv4 or IPv6 address */
			if (IN6_IS_ADDR_V4MAPPED((*mx)->addr)) {
				struct in6_addr ad;
				is_ip = (inet_pton(AF_INET6, host, &ad) > 0);
			} else {
				struct in_addr ad;
				is_ip = (inet_pton(AF_INET, host, &ad) > 0);
			}

			if (!is_ip) {
				struct ips *m = *mx;

				while (m != NULL) {
					m->name = strdup(host);
					if (m->name == NULL) {
						freeips(*mx);
						return -ENOMEM;
					}
					m = m->next;
				}
			}
		}
	}

	if (port != NULL) {
		char *more;

		*targetport = strtoul(port, &more, 10);
		if ((*more != '\0') || (*targetport >= 65536) || (*targetport == 0)) {
			const char *logmsg[] = {"invalid port number '", port,
					"' given for \"",
					host ? host : "",
					"\" given as target for \"", remhost, "\"", NULL};

			freeips(*mx);
			err_confn(logmsg, buf);
		}
	} else {
		*targetport = 25;
	}

	return 0;
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
	const char *curpart = remhost;
	/* check if the dir exists at all to avoid probing for every
	 * subdomain if the dir does not exist. */
	const int dirfd = get_dirfd(controldir_fd, "smtproutes.d");
	const size_t diroffs = 0;

	strcpy(fn + diroffs, remhost);

	*targetport = 25;

	if (dirfd >= 0) {
		while (1) {
			char **array;
			int fd = openat(dirfd, fn, O_RDONLY | O_CLOEXEC);
			const char *hv;
			const char *pv;

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

			close(dirfd);

			/* no error */
			if (loadlistfd(fd, &array, validroute) != 0) {
				const char *errmsg[] = {
						"error loading smtproute.d file for domain ",
						remhost, NULL};
				err_confn(errmsg, NULL);
			}

			if (tagmask & 1)
				/* find host */
				hv = tagvalue(array, 0);
			else
				hv = NULL;

			if (tagmask & 2)
				pv = tagvalue(array, 1);
			else
				pv = NULL;

			fd = parse_route_params(&mx, remhost, targetport, array, hv, pv);

			free(array);

			return (fd == 0) ? mx : NULL;
		}
	}

	if ((loadlistfd(openat(controldir_fd, "smtproutes", O_RDONLY | O_CLOEXEC), &smtproutes, hascolon) == 0) && (smtproutes != NULL)) {
		unsigned int k = 0;

		while (smtproutes[k]) {
			char *target = strchr(smtproutes[k], ':');
			*target++ = '\0';

			if (!*(smtproutes[k]) || matchdomain(remhost, reml, smtproutes[k])) {
				char *port;

				port = strchr(target, ':');
				if (port != NULL) {
					/* overwrite the colon ending the hostname so the code
					 * below will not take this as part of the host name */
					*port++ = '\0';
				}

				if (parse_route_params(&mx, remhost, targetport, smtproutes, *target ? target : NULL, port) != 0)
					return NULL;

				break;
			}
			k++;
		}
		free(smtproutes);
	}

	errno = 0;
	return mx;
}
