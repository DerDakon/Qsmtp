#ifndef CONN_H
#define CONN_H

#include "dns.h"

extern void tryconn(struct ips *);
extern void getmxlist(const char *, struct ips **);

#endif
