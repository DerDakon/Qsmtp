/** \file conn.h
 \brief headers of Qremote functions for connection establishing
 */
#ifndef CONN_H
#define CONN_H

#include <netinet/in.h>
#include "qdns.h"

unsigned int targetport;	/**< the port on the destination host to connect to */

extern void tryconn(struct ips *, const struct in6_addr *outip4, const struct in6_addr *outip6);
extern void getmxlist(char *, struct ips **);

#endif
