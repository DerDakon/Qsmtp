/** \file libowfatconn.h
 \brief function declarations for libowfat connector
 */
#ifndef QSMTP_LIBOWFAT_H
#define QSMTP_LIBOWFAT_H

#include <sys/types.h>

struct in6_addr;

extern int dnsip4(char **out, size_t *len, const char *host) __attribute__ ((nonnull (1,2,3)));
extern int dnsip6(char **out, size_t *len, const char *host) __attribute__ ((nonnull (1,2,3)));
extern int dnstxt(char **, const char *) __attribute__ ((nonnull (1,2)));
extern int dnsmx(char **out, size_t *len, const char *host) __attribute__ ((nonnull (1,2,3)));
extern int dnsname(char **, const struct in6_addr *) __attribute__ ((nonnull (1,2)));

#endif
