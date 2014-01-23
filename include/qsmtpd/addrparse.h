/** \file addrparse.h
 \brief headers of address parser functions
 */
#ifndef ADDRPARSE_H
#define ADDRPARSE_H

#include "sstring.h"

struct userconf;

extern int checkaddr(const char *const) __attribute__ ((pure)) __attribute__ ((nonnull (1)));
extern int addrsyntax(char *in, const int flags, string *addr, char **more) __attribute__ ((pure)) __attribute__ ((nonnull (1)));
extern int addrspec_valid(const char * const addr);

extern int addrparse(char *in, const int flags, string *addr, char **more, struct userconf *ds, const char *rcpthosts, const off_t rcpthsize) __attribute__ ((nonnull (1,5,6)));

/**
 * @brief check if the user identified by localpart and ds->domainpath exists
 * @param localpart localpart of mail address
 * @param ds path of domain
 * @retval 0 user doesn't exist
 * @retval 1 user exists
 * @retval 2 mail would be catched by .qmail-default and .qmail-default != vpopbounce
 * @retval 3 domain is not filtered (use for domains not local)
 * @retval 4 mail would be catched by .qmail-foo-default (i.e. mailinglist)
 * @retval 5 domain is not local
 * @retval -1 error, errno is set.
 *
 * If the user has it's own mail directory ds->userpath will be filled with
 * the correct values.
 *
 * This function must be implemented by the password backend (i.e. currently vpop.c).
 */
extern int user_exists(const string *localpart, const char *domain, struct userconf *ds);

#endif
