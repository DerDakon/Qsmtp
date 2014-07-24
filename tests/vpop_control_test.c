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

/* keep the product of those 2 great enough to overflow the buffer in getfile.c::open_in_dir() */
#define DIR_DEPTH 10
#define COMPONENT_LENGTH 64

/* name of the dummy files created */
#define EXISTING_FILENAME "filename"
#define EXISTING_FILENAME_CONTENT "content"
#define EXISTING_FILE_CONTENT "example.net"

static char fnbuffer[(COMPONENT_LENGTH + 1) * DIR_DEPTH + 20];
static struct userconf ds;

/* to satisfy the linker */
const char **globalconf;

int
pipe_move(int p[2] __attribute__((unused)), int target __attribute__((unused)))
{
	exit(EFAULT);
}

int
err_control(const char *fn)
{
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

static void
create_dirs(void)
{
	char dirname[COMPONENT_LENGTH + 2];
	unsigned int i;
	int r;
	char *fnstart;

	for (i = 0; i < sizeof(dirname) - 2; i++)
		dirname[i] = '0' + (i % 10);
	dirname[sizeof(dirname) - 2] = '/';
	dirname[sizeof(dirname) - 1] = '\0';

	for (i = 0; i < DIR_DEPTH; i++) {
		strcat(fnbuffer, dirname);
		r = mkdir(fnbuffer, 0755);
		if ((r != 0) && (errno != EEXIST)) {
			fprintf(stderr, "creating directory at level %u failed with error %i\n",
					i, errno);
			exit(1);
		}
	}

	fnstart = fnbuffer + strlen(fnbuffer);
	strcat(fnstart, EXISTING_FILENAME);
	r = creat(fnbuffer, 0644);
	if (r < 0) {
		fprintf(stderr, "cannot create target file, error %i\n",
				errno);
		exit(1);
	}
	close(r);

	*fnstart = '\0';
	strcat(fnstart, EXISTING_FILENAME_CONTENT);
	r = creat(fnbuffer, 0644);
	if (r < 0) {
		fprintf(stderr, "cannot create target file, error %i\n",
				errno);
		exit(1);
	} else {
		if (write(r, EXISTING_FILE_CONTENT "\n", strlen(EXISTING_FILE_CONTENT) + 1) != strlen(EXISTING_FILE_CONTENT) + 1) {
			fprintf(stderr, "cannot write into target file, error %i\n",
					errno);
			close(r);
			exit(1);
		}
	}
	close(r);
}

static int
check_open_fail(const char *range, const char *reason, const int error)
{
	int fd;
	enum config_domain type = -1;

	fd = getfile(&ds, "something", &type, 0);
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

	r += check_open_fail("user", "filename as path", ENOTDIR);

	ds.domainpath.s = fnbuffer;
	ds.domainpath.len = strlen(fnbuffer);
	fnbuffer[ds.domainpath.len++] = '/';
	fnbuffer[ds.domainpath.len] = '\0';
	close(ds.userdirfd);
	ds.userdirfd = -1;

	r += check_open_fail("domain", "filename as path", ENOTDIR);

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

	/* first: check with only user directory set */
	ds.userdirfd = get_dirfd(AT_FDCWD, fnbuffer);
	ds.domainpath.len = 0;
	ds.domainpath.s = NULL;

	fd = getfile(&ds, EXISTING_FILENAME, &type, 0);
	r += test_found_internal("user", fd, type, CONFIG_USER);

	/* set both, but user information should still be used */
	ds.domainpath.s = fnbuffer;
	ds.domainpath.len = strlen(fnbuffer);

	fd = getfile(&ds, EXISTING_FILENAME, &type, 0);
	r += test_found_internal("user", fd, type, CONFIG_USER);

	/* now only with domain information */
	close(ds.userdirfd);
	ds.userdirfd = -1;

	fd = getfile(&ds, EXISTING_FILENAME, &type, 0);
	r += test_found_internal("domain", fd, type, CONFIG_DOMAIN);

	fd = getfile(&ds, "something", &type, 1);
	if (fd != -1) {
		fprintf(stderr, "opening global file 'something' succeeded, type %i\n",
				type);
		close(fd);
		return r++;
	}

	return r;
}

static int
test_notfound(void)
{
	int r = 0;

	/* first: check with only user directory set */
	ds.userdirfd = get_dirfd(AT_FDCWD, fnbuffer);
	ds.domainpath.len = 0;
	ds.domainpath.s = NULL;

	r += check_open_fail("user", "nonexistent file", ENOENT);

	/* set both, but user information should still be used */
	ds.domainpath.s = fnbuffer;
	ds.domainpath.len = strlen(fnbuffer);

	r += check_open_fail("user", "nonexistent file", ENOENT);

	/* now only with domain information */
	close(ds.userdirfd);
	ds.userdirfd = -1;

	r += check_open_fail("domain", "nonexistent file", ENOENT);

	return r;
}

static int
test_getbuffer(void)
{
	int ret = 0;
	int r;
	char **array = NULL;

	ds.userdirfd = get_dirfd(AT_FDCWD, fnbuffer);
	ds.domainpath.len = 0;
	ds.domainpath.s = NULL;

	/* the file exists, but has no content */
	r = userconf_get_buffer(&ds, EXISTING_FILENAME, &array, NULL, 0);
	if (r != CONFIG_NONE) {
		fprintf(stderr, "opening empty file returned %i instead of CONFIG_NONE\n",
				r);
		ret++;
		free(array);
		array = NULL;
	}

	r = userconf_get_buffer(&ds, EXISTING_FILENAME_CONTENT, &array, NULL, 0);
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
	}
	free(array);
	array = NULL;

	r = userconf_get_buffer(&ds, "does_not_exist", &array, NULL, 1);
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
test_finddomain(void)
{
	int ret = 0;
	int r;

	ds.userdirfd = get_dirfd(AT_FDCWD, fnbuffer);
	ds.domainpath.len = 0;
	ds.domainpath.s = NULL;

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
		fprintf(stderr, "searching file with matching domain returned %i instead of CONFIG_USER\n",
				r);
		ret++;
	}

	close(ds.userdirfd);

	return ret;
}

int
main(void)
{
	int r = 0;
	char *slash;

	create_dirs();

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

	/* now test nonexisting */
	while (slash != NULL) {
		*(slash + 1) = '\0';

		r += test_notfound();

		fnbuffer[strlen(fnbuffer) - 1] = '\0';
		slash = strrchr(fnbuffer, '/');
	}

	return r;
}
