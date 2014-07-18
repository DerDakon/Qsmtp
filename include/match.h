/** \file match.h
 \brief functions for matching IP and domains against patterns
 */
#ifndef MATCH_H
#define MATCH_H

#include <netinet/in.h>
#include <sys/types.h>

extern int ip4_matchnet(const struct in6_addr *, const struct in_addr *, const unsigned char) __attribute__ ((nonnull (1,2)));
extern int ip6_matchnet(const struct in6_addr *, const struct in6_addr *, const unsigned char) __attribute__ ((nonnull (1,2)));
extern int matchdomain(const char *, const size_t, const char *) __attribute__ ((nonnull (1,3)));

#endif
