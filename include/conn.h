/** \file conn.h
 \brief headers of Qremote functions for connection establishing
 */
#ifndef CONN_H
#define CONN_H

#include <netinet/in.h>
#include "dns.h"

extern void tryconn(struct ips *, const struct in6_addr *);
extern void getmxlist(char *, struct ips **);

#endif
