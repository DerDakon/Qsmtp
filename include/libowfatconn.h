/** \file libowfatconn.h
 \brief function declarations for libowfat connector
 */
#ifndef QSMTP_LIBOWFAT_H
#define QSMTP_LIBOWFAT_H

/* lib/libowfatconn.c */

extern int dnsip4(char **, unsigned int *, const char *) __attribute__ ((nonnull (1,2,3)));
extern int dnsip6(char **, unsigned int *, const char *) __attribute__ ((nonnull (1,2,3)));
extern int dnstxt(char **, const char *) __attribute__ ((nonnull (1,2)));
extern int dnsmx(char **, unsigned int *, const char *) __attribute__ ((nonnull (1,2,3)));
extern int dnsname(char **, const char *) __attribute__ ((nonnull (1,2)));

#endif
