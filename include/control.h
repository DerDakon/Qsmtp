#ifndef CONTROL_H
#define CONTROL_H

#include <sys/types.h>

typedef int (*checkfunc)(const char *);

extern size_t lloadfilefd(int, char **, const int striptab);
extern int loadintfd(int, unsigned long *, const unsigned long def);
extern size_t loadoneliner(const char *, char **, int optional);
extern int loadlistfd(int, char **, char ***, checkfunc);
extern int finddomainmm(int, const char *);

#endif
