/** \file userconf.h
 \brief definition and functions for the userconf struct
 */
#ifndef USERCONF_H
#define USERCONF_H

#include <sstring.h>

struct userconf {
	string domainpath;              /**< Path of the domain for domain settings */
	string userpath;                /**< Path of the user directory where the user stores it's own settings */
	char **userconf;                /**< contents of the "filterconf" file in user directory (or NULL) */
	char **domainconf;              /**< dito for domain directory */
};

/**
 * @brief initialize the struct userconf
 * @param ds the struct to initialize
 *
 * All fields of the struct are reset to a safe invalid value.
 */
void userconf_init(struct userconf *ds);

/**
 * @brief free all information in a struct userconf
 * @param ds the struct to clear
 *
 * This will not free the struct itself so it is safe to use a static or
 * stack allocated struct. It will reset all values to a safe value so
 * the struct can be reused.
 */
void userconf_free(struct userconf *ds);

#endif
