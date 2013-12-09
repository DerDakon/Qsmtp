/** \file addrparse.h
 \brief headers of address parser functions
 */
#ifndef ADDRPARSE_H
#define ADDRPARSE_H

#include "sstring.h"

extern int checkaddr(const char *const) __attribute__ ((pure)) __attribute__ ((nonnull (1)));
extern int addrsyntax(char *in, const int flags, string *addr, char **more) __attribute__ ((pure)) __attribute__ ((nonnull (1)));
extern int addrspec_valid(const char * const addr);

#endif
