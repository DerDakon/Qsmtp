#include <qsmtpd/userfilters.h>
#include <qsmtpd/userconf.h>

#include <control.h>
#include <diropen.h>

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* name of the dummy files created */
#define EXISTING_FILENAME "filename"
#define EXISTING_FILENAME_CONTENT "content"
#define EXISTING_FILE_CONTENT "example.net"
#define EXISTING_FILTERCONF "filterconf"
#define EXISTING_FILTERCONF_CONTENT "helovalid="

static char fnbuffer[256] = "vp_control_test/domain/user/" EXISTING_FILENAME_CONTENT;
static struct userconf ds;

/* to satisfy the linker */
const char **globalconf;

static const char *expect_err_control;

int
pipe_move(int p[2] __attribute__((unused)), int target __attribute__((unused)))
{
	exit(EFAULT);
}

int
err_control(const char *fn)
{
	if ((expect_err_control != NULL) && (strcmp(expect_err_control, fn) == 0)) {
		expect_err_control = NULL;
		return 0;
	}

	fprintf(stderr, "unexpected call to %s(%s)\n",
		__func__, fn);
	exit(1);
}

int
err_control2(const char *msg, const char *fn)
{
	fprintf(stderr, "unexpected call to %s(%s, %s)\n",
		__func__, msg, fn);
	exit(1);
}

static int
check_open_fail(const char *range, const char *reason, const int error)
{
	int fd;
	enum config_domain type = -1;

	fd = getfile(&ds, "something", &type, userconf_none);
	if (fd != -1) {
		fprintf(stderr, "opening for %s for test '%s' succeeded, type %i\n",
				range, reason, type);
		close(fd);
		return 1;
	}

	if (errno != error) {
		fprintf(stderr, "opening for %s for test '%s' gave error %i, but not %i\n",
				range, reason, errno, error);
		return 1;
	}

	return 0;
}

static int
test_notdir(void)
{
	int r = 0;

	ds.userdirfd = open(fnbuffer, O_RDONLY | O_CLOEXEC);
	if (ds.userdirfd < 0) {
		fprintf(stderr, "cannot open %s: %i\n", fnbuffer, errno);
		return ++r;
	}

	r += check_open_fail("user", "filename as path", ENOTDIR);

	ds.domainpath.s = fnbuffer;
	ds.domainpath.len = strlen(fnbuffer);
	fnbuffer[ds.domainpath.len++] = '/';
	fnbuffer[ds.domainpath.len] = '\0';
	ds.domaindirfd = ds.userdirfd;
	ds.userdirfd = -1;

	r += check_open_fail("domain", "filename as path", ENOTDIR);

	close(ds.domaindirfd);

	return r;
}

static int
test_found_internal(const char *range, int fd, const int type, const enum config_domain expected_type)
{
	if (fd < 0) {
		fprintf(stderr, "error opening existing file for %s, errno %i\n",
				range, errno);
		return 1;
	}

	close(fd);
	if (type != expected_type) {
		fprintf(stderr, "existing file for %s did not return type %i, but type %i\n",
				range, expected_type, type);
		return 1;
	}

	return 0;
}

static int
test_found(void)
{
	int r = 0;
	int fd;
	enum config_domain type = -1;

	userconf_init(&ds);

	/* first: check with only user directory set */
	ds.userdirfd = get_dirfd(AT_FDCWD, fnbuffer);

	fd = getfile(&ds, EXISTING_FILENAME, &type, userconf_none);
	r += test_found_internal("user", fd, type, CONFIG_USER);

	/* set both, but user information should still be used */
	ds.domainpath.s = fnbuffer;
	ds.domainpath.len = strlen(fnbuffer);
	ds.domaindirfd = ds.userdirfd;

	fd = getfile(&ds, EXISTING_FILENAME, &type, userconf_none);
	r += test_found_internal("user", fd, type, CONFIG_USER);

	/* now only with domain information */
	ds.userdirfd = -1;

	fd = getfile(&ds, EXISTING_FILENAME, &type, userconf_none);
	r += test_found_internal("domain", fd, type, CONFIG_DOMAIN);

	fd = getfile(&ds, "something", &type, userconf_global);
	if (fd != -1) {
		fprintf(stderr, "opening global file 'something' succeeded, type %i\n",
				type);
		close(fd);
		r++;
	}

	close(ds.domaindirfd);

	return r;
}

static int
test_notfound(void)
{
	int r = 0;

	userconf_init(&ds);

	/* first: check with only user directory set */
	ds.userdirfd = get_dirfd(AT_FDCWD, fnbuffer);

	r += check_open_fail("user", "nonexistent file", ENOENT);

	/* set both, but user information should still be used */
	ds.domainpath.s = fnbuffer;
	ds.domainpath.len = strlen(fnbuffer);
	ds.domaindirfd = ds.userdirfd;

	r += check_open_fail("user", "nonexistent file", ENOENT);

	/* now only with domain information */
	ds.userdirfd = -1;

	r += check_open_fail("domain", "nonexistent file", ENOENT);

	close(ds.domaindirfd);

	return r;
}

static int
test_getbuffer(void)
{
	int ret = 0;
	int r;
	char **array = NULL;

	userconf_init(&ds);

	ds.userdirfd = get_dirfd(AT_FDCWD, fnbuffer);

	/* the file exists, but has no content */
	r = userconf_get_buffer(&ds, EXISTING_FILENAME, &array, NULL, userconf_none);
	if (r != CONFIG_NONE) {
		fprintf(stderr, "opening empty file returned %i instead of CONFIG_NONE\n",
				r);
		ret++;
		free(array);
		array = NULL;
	}

	r = userconf_get_buffer(&ds, EXISTING_FILENAME_CONTENT, &array, NULL, userconf_none);
	if (r != CONFIG_USER) {
		fprintf(stderr, "opening existing file returned %i instead of CONFIG_USER\n",
				r);
		ret++;
	} else if (array == NULL) {
		fprintf(stderr, "opening existing file returned empty array\n");
		ret++;
	} else if (strcmp(*array, EXISTING_FILE_CONTENT) != 0) {
		fprintf(stderr, "existing file should have returned 'example.net' as content, but returned '%s'\n",
				*array);
		ret++;
	} else if (array[1] != NULL) {
		fprintf(stderr, "existing file should have returned only 1 entry, but had more: %s\n", array[1]);
		ret++;
	}
	free(array);
	array = NULL;

	r = userconf_get_buffer(&ds, "does_not_exist", &array, NULL, userconf_global);
	if (r != CONFIG_NONE) {
		fprintf(stderr, "opening non-existent file returned %i instead of CONFIG_NONE\n",
				r);
		ret++;
	}
	if (array != NULL) {
		fprintf(stderr, "opening non-existent file returned a data buffer\n");
		ret++;
		free(array);
	}

	close(ds.userdirfd);

	return ret;
}

static int
test_getsetting(void)
{
	int ret = 0;
	long r;
	enum config_domain t = CONFIG_NONE;
	int fd;

	userconf_init(&ds);

	ds.userdirfd = get_dirfd(AT_FDCWD, fnbuffer);

	if (userconf_load_configs(&ds) != 0) {
		fprintf(stderr, "cannot load config settings (user only)\n");
		close(ds.userdirfd);
		return ++ret;
	}

	if ((ds.userconf == NULL) || (ds.domainconf != NULL)) {
		fprintf(stderr, "expected userconf != NULL, domainconf == NULL, but got u %p d %p\n",
				ds.userconf, ds.domainconf);
		ret++;
	}

	/* should be the user setting */
	r = getsetting(&ds, "helovalid", &t);
	if ((r != 7) || (t != CONFIG_USER)) {
		fprintf(stderr, "loading entry from user config returned %li type %i instead of 3/%i\n",
				r, t, CONFIG_USER);
		ret++;
	}

	free(ds.userconf);
	ds.userconf = NULL;

	/* set both, but user information should still be used */
	ds.domainpath.s = malloc(strlen(fnbuffer));
	if (ds.domainpath.s == NULL) {
		userconf_free(&ds);
		exit(ENOMEM);
	}
	ds.domainpath.len = strlen(fnbuffer) - 1;
	memcpy(ds.domainpath.s, fnbuffer, ds.domainpath.len);
	while (ds.domainpath.s[ds.domainpath.len - 1] != '/')
		ds.domainpath.len--;
	ds.domainpath.s[ds.domainpath.len] = '\0';
	ds.domaindirfd = get_dirfd(AT_FDCWD, ds.domainpath.s);

	if (userconf_load_configs(&ds) != 0) {
		fprintf(stderr, "cannot load config settings (user+domain)\n");
		userconf_free(&ds);
		return ++ret;
	}

	if ((ds.userconf == NULL) || (ds.domainconf == NULL)) {
		fprintf(stderr, "expected userconf != NULL, domainconf != NULL, but got u %p d %p\n",
				ds.userconf, ds.domainconf);
		ret++;
	}

	/* should be the user setting */
	r = getsetting(&ds, "helovalid", &t);
	if ((r != 7) || (t != CONFIG_USER)) {
		fprintf(stderr, "loading entry from user config returned %li type %i instead of 3/%i\n",
				r, t, CONFIG_USER);
		ret++;
	}

	/* now only with domain information */
	fd = ds.userdirfd;
	ds.userdirfd = -1;
	free(ds.userconf);
	ds.userconf = NULL;
	free(ds.domainconf);
	ds.domainconf = NULL;

	if (userconf_load_configs(&ds) != 0) {
		fprintf(stderr, "cannot load config settings (domain only)\n");
		ds.userdirfd = fd;
		userconf_free(&ds);
		return ++ret;
	}

	if ((ds.userconf != NULL) || (ds.domainconf == NULL)) {
		fprintf(stderr, "expected userconf == NULL, domainconf != NULL, but got u %p d %p\n",
				ds.userconf, ds.domainconf);
		ret++;
	}

	/* should be the user setting */
	r = getsetting(&ds, "helovalid", &t);
	if ((r != 3) || (t != CONFIG_DOMAIN)) {
		fprintf(stderr, "loading entry from user config returned %li type %i instead of 3/%i\n",
				r, t, CONFIG_USER);
		ret++;
	}

	/* free this one */
	ds.userdirfd = fd;

	userconf_free(&ds);

	return ret;
}

static int
test_finddomain(void)
{
	int ret = 0;
	int r;

	userconf_init(&ds);

	ds.userdirfd = get_dirfd(AT_FDCWD, fnbuffer);

	/* the does not file exist */
	r = userconf_find_domain(&ds, "does_not_exist", "example.org", 0);
	if (r != CONFIG_NONE) {
		fprintf(stderr, "opening non-existing file returned %i instead of CONFIG_NONE\n",
				r);
		ret++;
	}

	/* the file exists, but has no content */
	r = userconf_find_domain(&ds, EXISTING_FILENAME, "example.org", 0);
	if (r != CONFIG_NONE) {
		fprintf(stderr, "opening empty file returned %i instead of CONFIG_NONE\n",
				r);
		ret++;
	}

	/* the file content does not match the domain */
	r = userconf_find_domain(&ds, EXISTING_FILENAME_CONTENT, "example.org", 0);
	if (r != CONFIG_NONE) {
		fprintf(stderr, "searching file with non-matching domain returned %i instead of CONFIG_NONE\n",
				r);
		ret++;
	}

	/* the file content does not match the domain */
	r = userconf_find_domain(&ds, EXISTING_FILENAME_CONTENT, EXISTING_FILE_CONTENT, 0);
	if (r != CONFIG_USER) {
		fprintf(stderr, "searching file with matching domain returned %i instead of %i (CONFIG_USER)\n",
				r, CONFIG_USER);
		ret++;
	}

	/* the file content does not match the domain */
	ds.domaindirfd = ds.userdirfd;
	ds.userdirfd = -1;
	r = userconf_find_domain(&ds, EXISTING_FILENAME_CONTENT, EXISTING_FILE_CONTENT, 0);
	if (r != CONFIG_DOMAIN) {
		fprintf(stderr, "searching file with matching domain returned %i instead of (%i) CONFIG_DOMAIN\n",
				r, CONFIG_DOMAIN);
		ret++;
	}

	close(ds.domaindirfd);

	return ret;
}

int
main(void)
{
	int r = 0;
	char *slash;

	controldir_fd = -1;
	expect_err_control = "control/vpopbounce";
	r = userbackend_init();
	if (r != EBADF) {
		fprintf(stderr, "userbackend_init() with invalid controldir_fd returned %i instead of %i (EBADF)\n",
				r, EBADF);
		r = 1;
	} else {
		r = 0;
	}

	controldir_fd = AT_FDCWD;

	userconf_init(&ds);

	/* the buffer points to a filename, which is handled as directory */

	r += test_notdir();

	/* cut of the filename */
	fnbuffer[strlen(fnbuffer) - 1] = '\0';
	slash = strrchr(fnbuffer, '/');
	*(slash + 1) = '\0';

	r += test_found();
	r += test_getbuffer();
	r += test_finddomain();
	r += test_getsetting();

	/* now test nonexisting */
	while (slash != NULL) {
		*(slash + 1) = '\0';

		r += test_notfound();

		fnbuffer[strlen(fnbuffer) - 1] = '\0';
		slash = strrchr(fnbuffer, '/');
	}

	return r;
}
