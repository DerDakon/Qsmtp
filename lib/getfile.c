/** \file getfile.c
 \brief functions to get information from filterconf files
 */
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include "userfilters.h"
#include "control.h"

/**
 * check in user and domain directory if a file with given filename exists
 *
 * @param ds strings of user and domain directory
 * @param fn filename to search
 * @param type if user (0) or domain (1) directory matched, ignore this if (result == -1)
 * @return file descriptor of opened file
 * @retval -1 on error (errno is set)
 */
int
getfile(const struct userconf *ds, const char *fn, int *type)
{
	char *filename = NULL;
	int fd;
	const size_t len = strlen(fn);

	/* maybe there is no userpath because user only exists as .qmail-foo? */
	if (ds->userpath.len) {
		*type = 0;
		filename = malloc(ds->userpath.len + len + 1);
		if (filename == NULL) {
			return -1;
		}
		memcpy(filename, ds->userpath.s, ds->userpath.len);
		memcpy(filename + ds->userpath.len, fn, len + 1);

		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			if (errno != ENOENT) {
				free(filename);
				return -1;
			}
		} else {
			free(filename);
			return fd;
		}
	} else {
		if (!ds->domainpath.len) {
			errno = ENOENT;
			return -1;
		}
	}

	*type = 1;
	/* should only happen if !userpath.len */
	if (ds->domainpath.len > ds->userpath.len) {
		char *t = realloc(filename, ds->domainpath.len + len + 1);

		if (t == NULL) {
			free(filename);
			return -1;
		}
		filename = t;
	}

	memcpy(filename, ds->domainpath.s, ds->domainpath.len);
	memcpy(filename + ds->domainpath.len, fn, len + 1);
	fd = open(filename, O_RDONLY);
	free(filename);
	return fd;
}

/**
 * use getfile and fall back to /var/qmail/control if this finds nothing
 *
 * @param ds strings of user and domain directory
 * @param fn filename to search
 * @param type if user (0), domain (1) or global (2) directory matched, ignore this if (result == -1)
 * @return file descriptor of opened file
 * @retval -1 on error (errno is set)
 */
int
getfileglobal(const struct userconf *ds, const char *fn, int *type)
{
	int fd = getfile(ds, fn, type);
	size_t len;
	char *t;

	if ((fd != -1) || (errno != ENOENT))
		return fd;

	len = strlen(fn);
	/* neither user nor domain specified how to handle this feature
	 * now look up the global setting */

	*type = 2;
	if (! (t = malloc(len + 9))) {
		return -1;
	}
	memcpy(t, "control/", 8);
	memcpy(t + 8, fn, len + 1);
	fd = open(t, O_RDONLY);
	free(t);

	return fd;
}

/**
 * search a value in a given list of config values
 *
 * @param config list of settings, last entry has to be NULL, list may be NULL
 * @param flag the value to find
 * @param l strlen(flag)
 * @return the value assotiated with flag
 * @retval 0 no match
 * @retval -1 syntax error
 */
static long
checkconfig(const char * const *config, const char *flag, const size_t l)
{
	int i = 0;

	errno = 0;
	if (!config || !*config)
		return 0;
	while (config[i]) {
		if (!strncmp(config[i], flag, l)) {
			if (!config[i][l]) {
				/* only the name of the value is given: implicitely set to 1 */
				return 1;
			} else {
				if (config[i][l] == '=') {
					char *s;
					long r;

					r = strtol(config[i] + l + 1, &s, 10);
					if (*s) {
						errno = EINVAL;
						return -1;
					}
					return r;
				}
			}
		}
		i++;
	}
	return 0;
}

static long
getsetting_internal(const struct userconf *ds, const char *flag, int *type, const int useglobal)
{
	size_t l = strlen(flag);
	long r;

	*type = 0;
	r = checkconfig((const char **)ds->userconf, flag, l);
	if (r > 0) {
		return r;
	} else if (r < 0) {
		/* if user sets this to a value <0 this means "0 and don't override with domain setting" */
		if (errno)
			return r;
		return 0;
	}
	*type = 1;
	r = checkconfig((const char **)ds->domainconf, flag, l);
	if (r > 0) {
		return r;
	} else if (r < 0) {
		/* forced 0 from domain config */
		if (errno)
			return r;
		return 0;
	}
	if (!useglobal)
		return 0;

	*type = 2;
	r = checkconfig(globalconf, flag, l);
	if ((r < 0) && !errno)
		return 0;
	return r;
}

/**
 * get setting from user or domain filterconf file
 *
 * @param ds struct with the user/domain config info
 * @param flag name of the setting to find (case sensitive)
 * @param type if user (0) or domain (1) directory matched, ignore this if (result == -1)
 * @return value of setting
 * @retval 1 boolean setting or no number given
 * @retval 0 setting not found
 * @retval -1 on syntax error
 */
long
getsetting(const struct userconf *ds, const char *flag, int *type)
{
	return getsetting_internal(ds, flag, type, 0);
}

/**
 * use getsetting and fall back to /var/qmail/control if this finds nothing
 *
 * @param ds struct with the user/domain config info
 * @param flag name of the setting to find (case sensitive)
 * @param type if user (0), domain (1) or global (2) file matched, ignore this if (result == -1)
 * @return value of setting
 * @retval 1 boolean setting or no number given
 * @retval 0 setting not found
 * @retval -1 on syntax error
 */
long
getsettingglobal(const struct userconf *ds, const char *flag, int *type)
{
	return getsetting_internal(ds, flag, type, 1);
}
