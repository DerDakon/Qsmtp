/** \file qremote.h
 \brief definitions for common parts from Qremote exported from qremote.c
 */
#ifndef QREMOTE_H
#define QREMOTE_H 1

#include "sstring.h"

extern void err_mem(const int) __attribute__ ((noreturn));
extern void err_conf(const char *) __attribute__ ((noreturn)) __attribute__ ((nonnull (1)));
extern void err_confn(const char **) __attribute__ ((noreturn)) __attribute__ ((nonnull (1)));
extern void quit(void) __attribute__ ((noreturn));
extern int netget(void);
extern int checkreply(const char *, const char **, const int);

extern char *rhost;
extern size_t rhostlen;
extern char *partner_fqdn;
extern unsigned int smtpext;
extern string heloname;
extern size_t chunksize;

#endif
