/** \file addrparse.h
 \brief headers of address parser functions
 */
#ifndef ADDRPARSE_H
#define ADDRPARSE_H

#include "sstring.h"
#include "userfilters.h"

extern int checkaddr(const char *const) __attribute__ ((pure)) __attribute__ ((nonnull (1)));
extern int addrsyntax(char *in, const int flags, string *addr, char **more) __attribute__ ((pure)) __attribute__ ((nonnull (1)));
extern int addrspec_valid(const char * const addr);

extern int addrparse(char *in, const int flags, string *addr, char **more, struct userconf *ds, const char *rcpthosts, const off_t rcpthsize);

/* must be implemented by the password backend (i.e. currently vpop.c) */
extern int user_exists(const string *localpart, const char *domain, struct userconf *ds);

#endif
