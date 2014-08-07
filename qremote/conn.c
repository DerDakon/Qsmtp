/** \file conn.c
 \brief functions for establishing connection to remote SMTP server
 */

#include <qremote/conn.h>

#include <control.h>
#include <log.h>
#include <netio.h>
#include <qdns.h>
#include <qremote/client.h>
#include <qremote/qremote.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

unsigned int targetport = 25;

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif /* SOCK_CLOEXEC */

/**
 * @brief create a socket and connect to the given ip
 * @param remoteip the target address
 * @param outip the local IP the connection should originate from
 * @return the socket descriptor or a negative error code
 */
static int
conn(const struct in6_addr remoteip, const struct in6_addr *outip)
{
	int rc;
	int sd;

#ifdef IPV4ONLY
	struct sockaddr_in sock;

	sd = socket(PF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (sd < 0)
		return -errno;

	sock.sin_family = AF_INET;
	sock.sin_port = 0;
	sock.sin_addr.s_addr = outip->s6_addr32[3];

	if (bind(sd, (struct sockaddr *) &sock, sizeof(sock)) < 0) {
		int err = errno;
		close(sd);
		return -err;
	}

	sock.sin_port = htons(targetport);
	sock.sin_addr.s_addr = remoteip.s6_addr32[3];
#else
	struct sockaddr_in6 sock;

	sd = socket(PF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (sd < 0)
		return -errno;

	sock.sin6_family = AF_INET6;
	sock.sin6_port = 0;
	sock.sin6_flowinfo = 0;
	sock.sin6_addr = *outip;
	sock.sin6_scope_id = 0;

	if (bind(sd, (struct sockaddr *) &sock, sizeof(sock)) < 0) {
		int err = errno;
		close(sd);
		return -err;
	}

	sock.sin6_port = htons(targetport);
	sock.sin6_addr = remoteip;
#endif

	rc = connect(sd, (struct sockaddr *) &sock, sizeof(sock));

	if (rc < 0) {
		int err = errno;
		close(sd);
		return -err;
	}
	
	return  sd;
}

/**
 * try to estabish an SMTP connection to one of the hosts in the ip list
 *
 * @param mx list of IP adresses to try
 * @param outip4 local IPv4 to bind
 * @param outip6 local IPv6 to bind
 * @return the socket descriptor of the open connection
 * @retval -ENOENT no IP address left to connect to
 *
 * Every entry where a connection attempt was made is marked with a priority of
 * MX_PRIORITY_USED, the last one tried with MX_PRIORITY_CURRENT.
 */
int
tryconn(struct ips *mx, const struct in6_addr *outip4, const struct in6_addr *outip6)
{
	static unsigned short cur_s;

	while (1) {
		struct ips *thisip;
		const struct in6_addr *outip;
		int sd;

		for (thisip = mx; thisip; thisip = thisip->next) {
			if (thisip->priority == MX_PRIORITY_CURRENT) {
				if (cur_s < thisip->count - 1) {
					cur_s++;
					break;
				} else {
					thisip->priority = MX_PRIORITY_USED;
				}
			} else if (thisip->priority <= 65536) {
				cur_s = 0;
				/* set priority to MX_PRIORITY_CURRENT so this can be identified */
				thisip->priority = MX_PRIORITY_CURRENT;
				break;
			}
		}
		if (!thisip)
			return -ENOENT;

#ifdef IPV4ONLY
		(void) outip6;
#else
		if (!IN6_IS_ADDR_V4MAPPED(thisip->addr + cur_s))
			outip = outip6;
		else
#endif
			outip = outip4;

		sd = conn(thisip->addr[cur_s], outip);
		if (sd >= 0) {
			getrhost(thisip, cur_s);
			return sd;
		}
	}
}

/**
 * get all IPs for the MX entries of target address
 *
 * @param remhost target address
 * @param mx list of MX entries will be stored here, memory will be malloced
 */
void
getmxlist(char *remhost, struct ips **mx)
{
	size_t reml = strlen(remhost);

	if (remhost[0] == '[') {
		const char *logmsg[] = {"parse error in first argument \"",
					remhost, "\"", NULL};

		if (remhost[reml - 1] == ']') {
			*mx = malloc(sizeof(**mx));
			if (!*mx)
				err_mem(0);

			memset(*mx, 0, sizeof(**mx));
#ifndef NEW_IPS_LAYOUT
			(*mx)->addr = &(*mx)->ad;
#else
			(*mx)->addr = malloc(sizeof(*(*mx)->addr));
			if ((*mx)->addr == NULL) {
				free(*mx);
				err_mem(0);
			}
			(*mx)->addr->s6_addr32[0] = ntohl(0);
			(*mx)->addr->s6_addr32[1] = ntohl(0);
#endif
			(*mx)->count = 1;

			remhost[reml - 1] = '\0';
			if (inet_pton(AF_INET6, remhost + 1, (*mx)->addr) > 0) {
				remhost[reml - 1] = ']';
				return;
			} else if (inet_pton(AF_INET, remhost + 1, &((*mx)->addr->s6_addr32[3])) > 0) {
				(*mx)->addr->s6_addr32[2] = ntohl(0xffff);
				remhost[reml - 1] = ']';
				return;
			}
			remhost[reml - 1] = ']';
			freeips(*mx);
		}

		log_writen(LOG_ERR, logmsg);
		write_status("Z4.3.0 parse error in first argument");
		net_conn_shutdown(shutdown_abort);
	}

	*mx = smtproute(remhost, reml, &targetport);
	if ((*mx == NULL) && (errno != 0)) {
		assert(errno == ENOMEM);
		err_mem(0);
	}

	if (!*mx) {
		if (ask_dnsmx(remhost, mx)) {
			const char *msg[] = { "Z4.4.3 cannot find a mail exchanger for ",
					remhost };
			write_status_m(msg, 2);
			net_conn_shutdown(shutdown_abort);
		}
	}
}
