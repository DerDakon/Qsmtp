#ifndef QREMOTE_H
#define QREMOTE_H 1

extern void __attribute__ ((noreturn)) err_mem(const int);
extern void __attribute__ ((noreturn)) err_conf(const char *);
extern void __attribute__ ((noreturn)) err_confn(const char **);
extern void __attribute__ ((noreturn)) quit(void);
extern int netget(void);

extern char *rhost;
extern size_t rhostlen;
extern char *partner_fqdn;

#endif
