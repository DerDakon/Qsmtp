#ifndef CONTROL_H
#define CONTROL_H

typedef int (*checkfunc)(const char *);

extern int lloadfilefd(int, char **, const int striptab);
extern int loadintfd(int, unsigned long *, const unsigned long def);
extern int loadoneliner(const char *, char **, int optional);
extern int loadlistfd(int, char **, char ***, checkfunc);
extern int finddomainmm(int, const char *);

#endif
