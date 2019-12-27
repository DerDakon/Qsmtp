/** \file common_setup.c
 \brief setup function shared between Qremote and Qsurvey
 */

#include <qremote/qremote.h>

#include <control.h>
#include <diropen.h>
#include <netio.h>
#include <qdns.h>
#include <qmaildir.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

string heloname;
struct in6_addr outgoingip;
struct in6_addr outgoingip6;

void
remote_common_setup(void)
{
	unsigned long tmp;
	char *ipbuf;

	if (chdir(AUTOQMAIL))
		err_conf("cannot chdir to qmail directory");

	controldir_fd = get_dirfd(-1, AUTOQMAIL "/control");
	if (controldir_fd < 0)
		err_conf("cannot get a file descriptor for " AUTOQMAIL "/control");

	int j = loadoneliner(controldir_fd, "helohost", &heloname.s, 1);
	if (j < 0) {
		if ( ( j = loadoneliner(controldir_fd, "me", &heloname.s, 0) ) < 0 )
			err_conf("can open neither control/helohost nor control/me");
		if (domainvalid(heloname.s))
			err_conf("control/me contains invalid name");
	} else {
		if (domainvalid(heloname.s))
			err_conf("control/helohost contains invalid name");
	}
	heloname.len = j;

	if (loadintfd(openat(controldir_fd, "timeoutremote", O_RDONLY | O_CLOEXEC), &tmp, 320) < 0)
		err_conf("parse error in control/timeoutremote");

	timeout = tmp;

	if (((ssize_t)loadoneliner(controldir_fd, "outgoingip", &ipbuf, 1)) >= 0) {
		int r = inet_pton(AF_INET6, ipbuf, &outgoingip);

		if (r <= 0)
			r = inet_pton_v4mapped(ipbuf, &outgoingip);

		free(ipbuf);
		if (r <= 0)
			err_conf("parse error in control/outgoingip");

		if (!IN6_IS_ADDR_V4MAPPED(&outgoingip))
			err_conf("found IPv6 address in control/outgoingip");
	} else {
		outgoingip = in6addr_any;
	}

#ifndef IPV4ONLY
	if (((ssize_t)loadoneliner(controldir_fd, "outgoingip6", &ipbuf, 1)) >= 0) {
		int r = inet_pton(AF_INET6, ipbuf, &outgoingip6);

		free(ipbuf);
		if (r <= 0)
			err_conf("parse error in control/outgoingip6");

		if (IN6_IS_ADDR_V4MAPPED(&outgoingip6))
			err_conf("control/outgoingip6 has IPv4 address");
	} else
#endif
		outgoingip6 = in6addr_any;
}
