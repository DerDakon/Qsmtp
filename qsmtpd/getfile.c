/** \file getfile.c
 \brief functions to get information from filterconf files
 */
#include <control.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <qsmtpd/userconf.h>
#include <qsmtpd/userfilters.h>

/**
 * @brief open a file in the given directory
 * @param dirname the path of the directory
 * @param dirlen strlen(dirname)
 * @param fn the name of the file
 * @return the file descriptor of the opened file
 * @retval -1 no file descriptor could be opened (errno is set)
 *
 * dirname has to end in a '/'.
 */
static int
open_in_dir(const char *dirname, const size_t dirlen, const char *fn)
{
	int fd;

	char sbuf[512];		/* a static buffer, should be long enough for most cases */
	char *dbuf = NULL;	/* in case sbuf is too short */
	char *buf;		/* pointer to the one actually used */
	const size_t pathlen = dirlen + strlen(fn) + 1;

	if (pathlen < sizeof(sbuf)) {
		buf = sbuf;
	} else {
		dbuf = malloc(pathlen);
		if (dbuf == NULL)
			return -1;
		buf = dbuf;
	}

	memcpy(buf, dirname, dirlen);
	memcpy(buf + dirlen, fn, pathlen - dirlen);

	fd = open(buf, O_RDONLY |  O_CLOEXEC);

	free(dbuf);

	return fd;
}

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
	int fd;

	if (ds->userpath.len) {
		*type = 0;

		fd = open_in_dir(ds->userpath.s, ds->userpath.len, fn);

		if ((fd >= 0) || (errno != ENOENT))
			return fd;
	}

	if (!ds->domainpath.len) {
		errno = ENOENT;
		return -1;
	}

	*type = 1;

	return open_in_dir(ds->domainpath.s, ds->domainpath.len, fn);
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
	static const char controldir[] = "control/";

	if ((fd != -1) || (errno != ENOENT))
		return fd;

	/* neither user nor domain specified how to handle this feature
	 * now look up the global setting */
	*type = 2;
	return open_in_dir(controldir, strlen(controldir), fn);
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
