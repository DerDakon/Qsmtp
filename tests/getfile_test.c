#include <qsmtpd/userfilters.h>
#include <qsmtpd/userconf.h>

#include "control.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h> 
#include <sys/types.h> 

/* keep the product of those 2 great enough to overflow the buffer in getfile.c::open_in_dir() */
#define DIR_DEPTH 10
#define COMPONENT_LENGTH 64

/* name of the dummy file created */
#define EXISTING_FILENAME "filename"

static char fnbuffer[(COMPONENT_LENGTH + 1) * DIR_DEPTH + 20];
static struct userconf ds;

/* to satisfy the linker */
const char **globalconf;

static void
create_dirs(void)
{
	char dirname[COMPONENT_LENGTH + 2];
	unsigned int i;
	int r;

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

	strcat(fnbuffer, EXISTING_FILENAME);
	r = creat(fnbuffer, 0644);
	if (r < 0) {
		fprintf(stderr, "cannot create target file, error %i\n",
				errno);
		exit(1);
	}
	close(r);
}

static int
check_open_fail(const char *range, const char *reason, const int error)
{
	int fd;
	int type = -1;

	fd = getfile(&ds, "something", &type);
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

	ds.userpath.s = fnbuffer;
	ds.userpath.len = strlen(fnbuffer);
	fnbuffer[ds.userpath.len++] = '/';
	fnbuffer[ds.userpath.len] = '\0';

	r += check_open_fail("user", "filename as path", ENOTDIR);

	ds.domainpath.len = ds.userpath.len;
	ds.domainpath.s = ds.userpath.s;
	ds.userpath.len = 0;
	ds.userpath.s = NULL;

	r += check_open_fail("domain", "filename as path", ENOTDIR);

	return r;
}

static int
test_found_internal(const char *range, int fd, int type, int expected_type)
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
	int type = -1;

	/* first: check with only user directory set */
	ds.userpath.s = fnbuffer;
	ds.userpath.len = strlen(fnbuffer);
	ds.domainpath.len = 0;
	ds.domainpath.s = NULL;

	fd = getfile(&ds, EXISTING_FILENAME, &type);
	r += test_found_internal("user", fd, type, 0);

	/* set both, but user information should still be used */
	ds.domainpath.len = ds.userpath.len;
	ds.domainpath.s = ds.userpath.s;

	fd = getfile(&ds, EXISTING_FILENAME, &type);
	r += test_found_internal("user", fd, type, 0);

	/* now only with domain information */
	ds.userpath.len = 0;
	ds.userpath.s = NULL;

	fd = getfile(&ds, EXISTING_FILENAME, &type);
	r += test_found_internal("domain", fd, type, 1);

	return 0;
}

static int
test_notfound(void)
{
	int r = 0;

	/* first: check with only user directory set */
	ds.userpath.s = fnbuffer;
	ds.userpath.len = strlen(fnbuffer);
	ds.domainpath.len = 0;
	ds.domainpath.s = NULL;

	r += check_open_fail("user", "nonexistent file", ENOENT);

	/* set both, but user information should still be used */
	ds.domainpath.len = ds.userpath.len;
	ds.domainpath.s = ds.userpath.s;

	r += check_open_fail("user", "nonexistent file", ENOENT);

	/* now only with domain information */
	ds.userpath.len = 0;
	ds.userpath.s = NULL;

	r += check_open_fail("domain", "nonexistent file", ENOENT);

	return 0;
}

int
main()
{
	int r = 0;
	char *slash;

	create_dirs();

	memset(&ds, 0, sizeof(ds));

	/* the buffer points to a filename, which is handled as directory */

	r += test_notdir();

	/* cut of the filename */
	fnbuffer[strlen(fnbuffer) - 1] = '\0';
	slash = strrchr(fnbuffer, '/');
	*(slash + 1) = '\0';

	r += test_found();

	/* now test nonexisting */
	while (slash != NULL) {
		*(slash + 1) = '\0';

		r += test_notfound();

		fnbuffer[strlen(fnbuffer) - 1] = '\0';
		slash = strrchr(fnbuffer, '/');
	}

	return r;
}
