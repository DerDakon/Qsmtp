/** \file control.h
 \brief headers of functions for control file handling
 */
#ifndef CONTROL_H
#define CONTROL_H

#include <sys/types.h>

typedef int (*checkfunc)(const char *);

extern size_t lloadfilefd(int, char **, const int striptab);
extern int loadintfd(int, unsigned long *, const unsigned long def);
extern size_t loadoneliner(const char *, char **, const int optional);
extern size_t loadonelinerfd(int fd, char **buf);
extern int loadlistfd(int, char **, char ***, checkfunc);
extern int finddomainfd(int, const char *, const int);
extern int finddomainmm(const char *, const off_t, const char *);

#endif
