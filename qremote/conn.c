#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include "dns.h"
#include "control.h"
#include "match.h"
#include "log.h"
#include "qremote.h"

extern int socketd;
static unsigned long targetport = 25;
static char *user;
static char *pass;

static int
conn(const struct in6_addr remoteip)
{
	int rc;
#ifdef IPV4ONLY
	struct sockaddr_in sock;

	socketd = socket(PF_INET, SOCK_STREAM, 0);

	if (socketd < 0)
		return errno;

	sock.sin_family = AF_INET;
	sock.sin_port = 0;
	sock.sin_addr.s_addr = INADDR_ANY;

	rc = bind(socketd, (struct sockaddr *) &sock, sizeof(sock));

	if (rc)
		return errno;

	sock.sin_port = htons(targetport);
	sock.sin_addr.s_addr = remoteip.s6_addr32[3];
#else
	struct sockaddr_in6 sock;

	socketd = socket(PF_INET6, SOCK_STREAM, 0);

	if (socketd < 0)
		return errno;

	sock.sin6_family = AF_INET6;
	sock.sin6_port = 0;
	sock.sin6_flowinfo = 0;
	sock.sin6_addr = in6addr_any;
	sock.sin6_scope_id = 0;

	rc = bind(socketd, (struct sockaddr *) &sock, sizeof(sock));

	if (rc)
		return errno;

	sock.sin6_port = htons(targetport);
	sock.sin6_addr = remoteip;
#endif

	return connect(socketd, (struct sockaddr *) &sock, sizeof(sock)) ? errno : 0;
}

/**
 * tryconn - try to estabish an SMTP connection to one of the hosts in the ip list
 *
 * @mx: list of IP adresses to try
 *
 * Every entry where a connection attempt was made is marked with a priority of 65537
 */
void
tryconn(struct ips *mx)
{
	struct ips *thisip;

	thisip = mx;
	while (1) {
		unsigned int minpri = 65537;

#ifdef IPV4ONLY
		for (thisip = mx; thisip; thisip = thisip->next) {
			if (!IN6_IS_ADDR_V4MAPPED(&thisip->addr))
				thisip->priority = 65537;
		}
#endif
		for (thisip = mx; thisip; thisip = thisip->next) {
			if (thisip->priority < minpri)
				minpri = thisip->priority;
		}
		if (minpri == 65537) {
			close(socketd);
			write(1, "Zcan't connect to any server\n", 30);
			exit(0);
		}
		for (thisip = mx; thisip; thisip = thisip->next) {
			if (thisip->priority == minpri) {
				thisip->priority = 65537;

				if (!conn(thisip->addr))
					return;
			}
		}
	}
}

static int
hascolon(const char *s)
{
	char *colon = strchr(s, ':');

	if (!*colon)
		return 0;
	return (*(colon + 1) == ':');
}

void
getmxlist(char *remhost, struct ips **mx)
{
	char **smtproutes, *smtproutbuf;
	size_t reml = strlen(remhost);

	if (remhost[0] == '[') {
		if (remhost[reml - 1] == ']') {
			*mx = malloc(sizeof(**mx));
			if (!*mx) {
				err_mem(0);
			}

			remhost[reml - 1] = '\0';
			if (inet_pton(AF_INET6, remhost + 1, &((*mx)->addr)) > 0) {
				(*mx)->priority = 0;
				(*mx)->next = NULL;
				return;
			} else if (inet_pton(AF_INET, remhost + 1, &((*mx)->addr.s6_addr32[3])) > 0) {
				memset((*mx)->addr.s6_addr32, 0, 12);
				(*mx)->priority = 0;
				(*mx)->next = NULL;
				return;
			}
		}
		log_write(LOG_ERR, "parse error in first argument");
		write(1, "Z4.3.0 parse error in first argument\n", 38);
		exit(0);
	}

	if (!loadlistfd(open("control/smtproutes", O_RDONLY), &smtproutbuf, &smtproutes, hascolon) && smtproutbuf) {
		char *target;
		unsigned int k = 0;

		while (smtproutes[k]) {
			target = strchr(smtproutes[k], ':');
			*target++ = '\0';

			if (matchdomain(remhost, reml, smtproutes[k])) {
				char *port;

				port = strchr(target, ':');
				if (port) {
					char *more;

					*port++ = '\0';
					if ((more = strchr(port, ':'))) {
						char *tmp;

						*more++ = '\0';
						tmp = strchr(more, ':');
						if (tmp && *(tmp + 1)) {
							user = malloc(tmp - more + 1);
							pass = malloc(strlen(tmp));
							if (!pass || !user) {
								err_mem(0);
							}
							memcpy(user, more, tmp - more);
							user[tmp - more] = '\0';
							memcpy(pass, tmp + 1, strlen(tmp + 1));
							pass[strlen(tmp + 1)] = '\0';
						}
					}
					targetport = strtoul(port, &more, 10);
					if (*more || (targetport >= 65536)) {
						const char *logmsg[] = {"invalid port number given for \"",
									target, "\" given as target for \"",
									remhost, "\"", NULL};

						err_confn(logmsg);
					}
				}
				if (ask_dnsaaaa(target, mx)) {
					const char *logmsg[] = {"cannot find IP address for static route \"",
									target, "\" given as target for \"",
									remhost, "\"", NULL};

					err_confn(logmsg);
				} else {
					break;
				}
			}
			k++;
		}
		free(smtproutes);
		free(smtproutbuf);
	}

	if (!*mx) {
		if (ask_dnsmx(remhost, mx)) {
			write(1, "Z4.4.3 cannot find a mail exchanger for ", 40);
			write(1, remhost, reml);
			write(1, "\n", 2);
			exit(0);
		}
	}
}
