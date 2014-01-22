/** \file control.h
 \brief headers of functions for control file handling
 */
#ifndef CONTROL_H
#define CONTROL_H

#include <sys/types.h>

typedef int (*checkfunc)(const char *);

extern size_t lloadfilefd(int, char **, const int striptab) __attribute__ ((nonnull (2)));
extern int loadintfd(int, unsigned long *, const unsigned long def) __attribute__ ((nonnull (2)));
extern size_t loadoneliner(const char *, char **, const int optional) __attribute__ ((nonnull (1, 2)));
extern size_t loadonelinerfd(int fd, char **buf) __attribute__ ((nonnull (2)));
extern int loadlistfd(int, char ***, checkfunc) __attribute__ ((nonnull (2)));
extern int finddomainfd(int, const char *, const int) __attribute__ ((nonnull (2)));
extern int finddomain(const char *buf, const off_t size, const char *domain) __attribute__ ((nonnull (3)));

#endif
