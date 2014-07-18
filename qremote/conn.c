/** \file conn.c
 \brief functions for establishing connection to remote SMTP server
 */

#include <qremote/conn.h>

#include <control.h>
#include <log.h>
#include <netio.h>
#include <qdns.h>
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

	sd = socket(PF_INET, SOCK_STREAM, 0);

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

	sd = socket(PF_INET6, SOCK_STREAM, 0);

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
 *
 * Every entry where a connection attempt was made is marked with a priority of 65537,
 * the last one tried with 65538
 */
int
tryconn(struct ips *mx, const struct in6_addr *outip4, const struct in6_addr *outip6)
{
	while (1) {
		struct ips *thisip;
		const struct in6_addr *outip;
		int sd;

		for (thisip = mx; thisip; thisip = thisip->next) {
			if (thisip->priority == 65538)
				thisip->priority = 65537;
			if (thisip->priority <= 65536)
				break;
		}
		if (!thisip) {
			write_status("Z4.4.2 can't connect to any server");
			exit(0);
		}

#ifndef IPV4ONLY
		if (!IN6_IS_ADDR_V4MAPPED(&thisip->addr))
			outip = outip6;
		else
#else
		(void) outip6;
#endif
			outip = outip4;

		sd = conn(thisip->addr, outip);
		if (sd >= 0) {
			/* set priority to 65538 to allow getrhost() to find active MX */
			thisip->priority = 65538;
			return sd;
		}
		thisip->priority = 65537;
	}
}

/**
 * @brief set IPv6 addresses as already used
 * 
 * @param mx list of addresses
 *
 * This will mark all IPv6 addresses as already used in case this is
 * compiled as only supporting IPv4 addresses. Otherwise it does nothing.
 */
static void
remove_ipv6(struct ips **mx)
{
#ifdef IPV4ONLY
	struct ips *thisip;

	for (thisip = *mx; thisip; thisip = thisip->next) {
		if (!IN6_IS_ADDR_V4MAPPED(&thisip->addr))
			thisip->priority = 65537;
	}
#else
	(void) mx;
#endif
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

			remhost[reml - 1] = '\0';
			if (inet_pton(AF_INET6, remhost + 1, &((*mx)->addr)) > 0) {
				remhost[reml - 1] = ']';
				remove_ipv6(mx);
				return;
			} else if (inet_pton(AF_INET, remhost + 1, &((*mx)->addr.s6_addr32[3])) > 0) {
				(*mx)->addr.s6_addr32[2] = ntohl(0xffff);
				remhost[reml - 1] = ']';
				return;
			}
			remhost[reml - 1] = ']';
			free(*mx);
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

	remove_ipv6(mx);
}
