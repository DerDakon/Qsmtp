#ifndef MATCH_H
#define MATCH_H

#include <sys/types.h>
#include <netinet/in.h>

extern int ip4_matchnet(const struct in6_addr *, const struct in_addr *, const unsigned char);
extern int ip6_matchnet(const struct in6_addr *, const struct in6_addr *, const unsigned char);
extern int matchdomain(const char *, const size_t, const char *);

#endif
