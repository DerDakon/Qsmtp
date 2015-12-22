/** \file userconf.h
 \brief definition of the helper functions around the user configuration
 */
#ifndef USERCONF_H
#define USERCONF_H

#include <control.h>
#include <sstring.h>

struct userconf {
	string domainpath;		/**< Path of the domain for domain settings */
	char **userconf;		/**< contents of the "filterconf" file in user directory (or NULL) */
	char **domainconf;		/**< dito for domain directory */
	int domaindirfd;		/**< descriptor of the domain settings directory */
	int userdirfd;			/**< descriptor of the user directory where the user stores it's own settings */
};

enum userconf_flags {
	userconf_none = 0,		/**< no special search options to use */
	userconf_global = 1,		/**< global configuration lookup should be performed */
	userconf_inherit = 2		/**< allow "!inherit" command to merge with domain/global settings */
};

/**
 * @brief initialize the struct userconf
 * @param ds the struct to initialize
 *
 * All fields of the struct are reset to a safe invalid value.
 */
void userconf_init(struct userconf *ds) __attribute__ ((nonnull (1)));

/**
 * @brief free all information in a struct userconf
 * @param ds the struct to clear
 *
 * This will not free the struct itself so it is safe to use a static or
 * stack allocated struct. It will reset all values to a safe value so
 * the struct can be reused.
 */
void userconf_free(struct userconf *ds) __attribute__ ((nonnull (1)));

/**
 * @brief load the filter settings for user and domain
 * @param ds the userconf buffer to hold the information
 * @return if filters were successfully loaded or error code
 * @retval 0 filters were loaded (or no configuration is present)
 * @retval >0 error code
 */
int userconf_load_configs(struct userconf *ds) __attribute__ ((nonnull (1)));

/**
 * @brief get a config buffer for a given user or domain
 * @param ds the userconf buffer
 * @param key the key name to load the information for
 * @param values the result array
 * @param cf a function to filter the entries (may be NULL)
 * @param flags search flags
 * @return the type of the configuration entry returned
 * @retval <0 negative error code
 */
int userconf_get_buffer(const struct userconf *ds, const char *key, char ***values, checkfunc cf, const unsigned int flags) __attribute__ ((nonnull (1,2,3)));

/**
 * @brief find a domain in the user configuration key
 * @param ds the userconf buffer
 * @param key the key name for lookup
 * @param domain the domain name to search for
 * @param flags search flags
 * @return the type of the configuration entry returned
 * @retval CONFIG_NONE the domain was not found in the configuration
 * @retval >0 the domain was found in the configuration
 * @retval <0 negative error code
 */
int userconf_find_domain(const struct userconf *ds, const char *key, const char *domain, const unsigned int flags) __attribute__ ((nonnull (1,2,3)));

/**
 * @brief initialize the backend to query for local users
 * @return if initialization was successful
 * @retval 0 backend was successfully initialized
 * @retval >0 error code
 */
int userbackend_init(void);

/**
 * @brief free the resources needed by the user backend
 */
void userbackend_free(void);

#endif
