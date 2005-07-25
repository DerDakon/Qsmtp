/** \file conn.h
 \brief headers of Qremote functions for connection establishing
 */
#ifndef CONN_H
#define CONN_H

#include "dns.h"

extern void tryconn(struct ips *);
extern void getmxlist(char *, struct ips **);

#endif
