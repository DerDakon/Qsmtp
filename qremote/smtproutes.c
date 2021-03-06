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
#include <qremote/starttlsr.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

static char *clientcertbuf;	/**< buffer for a user-defined client certificate location */
char *clientkeybuf;	/**< buffer for a user-defined client key location */
bool expect_tls;	/**< if TLS is expected: if clientcertbuf is set and not from the default file */

static const char *tags[] = {
	"relay",
	"port",
	"clientcert",
	"clientkey",
	"outgoingip",
	"outgoingip6",
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

/**
 * @brief callback for loadlistfd() to check validity of smtprouts.d file contents
 * @param s the line to check
 *
 * This not only checks the current line, but also sets tagmask to detect duplicate
 * lines.
 */
static int
validroute(const char *s)
{
	const char *last = strchr(s, '=');

	/* must be key=value */
	if (last == NULL)
		return 1;

	/* catch empty keys */
	if (last == s)
		return 1;

	size_t len = last - s;

	for (unsigned int i = 0; tags[i] != NULL; i++) {
		/* catch if tag is longer than the key found here */
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
				(*mx)->name = strdup(host);
				if ((*mx)->name == NULL) {
					freeips(*mx);
					return -ENOMEM;
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
	/* check if the dir exists at all to avoid probing for every
	 * subdomain if the dir does not exist. */
	const int dirfd = get_dirfd(controldir_fd, "smtproutes.d");

	*targetport = 25;
	expect_tls = false;

	if (dirfd >= 0) {
		char fnbuf[DOMAINNAME_MAX + 2];
		const char *fn = remhost;
		const char *curpart = remhost;
		bool is_default_file = false;

		while (1) {
			char **array;
			const char *hv = NULL;
			const char *pv = NULL;
			unsigned int i;
			int fd = openat(dirfd, fn, O_RDONLY | O_CLOEXEC);

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
						fn = "default";
						curpart = NULL;
						is_default_file = true;
					} else {
						assert(strlen(dot) < sizeof(fnbuf) - 2);
						fnbuf[0] = '*';
						strcpy(fnbuf + 1, dot);
						fn = fnbuf;

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

			for (i = 0; tags[i] != NULL; i++) {
				const char *v;
				if (!(tagmask & (1 << i)))
					continue;

				v = tagvalue(array, i);

				switch (i) {
				case 0:
					/* find host */
					hv = v;
					break;
				case 1:
					/* find port */
					pv = v;
					break;
				case 2:
					if (access(v, R_OK) != 0) {
						const char *logmsg[] = { "invalid certificate '", v,
									"' given for \"", remhost, "\"", NULL };

						err_confn(logmsg, array);
					} else {
						clientcertbuf = strdup(v);
						if (clientcertbuf == NULL) {
							free(array);
							err_mem(0);
						}
						expect_tls = !is_default_file;
					}
					break;
				case 3:
					if (access(v, R_OK) != 0) {
						const char *logmsg[] = { "invalid key '", v,
									"' given for \"", remhost, "\"", NULL };

						err_confn(logmsg, array);
					} else {
						clientkeybuf = strdup(v);
						if (clientkeybuf == NULL) {
							free(array);
							err_mem(0);
						}
					}
					break;
				case 4:
					if (inet_pton_v4mapped(v, &outgoingip) <= 0) {
						const char *logmsg[] = { "invalid outgoingip '", v, "' given for \"",
								remhost, "\"", NULL };
						err_confn(logmsg, array);
					}
					break;
				case 5:
					if (inet_pton(AF_INET6, v, &outgoingip6) <= 0) {
						const char *logmsg[] = { "invalid outgoingip6 '", v, "' given for \"",
								remhost, "\"", NULL };
						err_confn(logmsg, array);
					}

					if (IN6_IS_ADDR_V4MAPPED(&outgoingip6)) {
						const char *logmsg[] = { "IPv4 mapped address '", v,
								"' in outgoingip6 for \"", remhost, "\"", NULL };

						err_confn(logmsg, array);
					}

					break;
				default:
					assert(0);
				}
			}

			struct ips *mx = NULL;
			fd = parse_route_params(&mx, remhost, targetport, array, hv, pv);
			free(array);
			if (fd != 0) {
				free_smtproute_vals();
				return NULL;
			}
			if (clientcertbuf) {
				clientcertname = clientcertbuf;
				clientkeyname = clientcertbuf;
			}
			if (clientkeybuf)
				clientkeyname = clientkeybuf;
			errno = 0;
			return mx;
		}
	} else {
		/* check if default client certificate exists */
		if (faccessat(controldir_fd, "clientkey.pem", R_OK, 0) == 0)
			clientkeyname = "control/clientkey.pem";
	}

	char **smtproutes;
	struct ips *mx = NULL;
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

/**
 * @brief free values loaded from smtproutes
 */
void
free_smtproute_vals()
{
	free(clientcertbuf);
	clientcertbuf = NULL;
	expect_tls = false;
	free(clientkeybuf);
	clientkeybuf = NULL;
	clientcertname = "control/clientcert.pem";
	clientkeyname = clientcertname;
}
