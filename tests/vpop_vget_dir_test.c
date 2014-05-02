#include "cdb_entries.h"
#include "test_io/testcase_io.h"

#include <cdb.h>
#include <qsmtpd/vpop.h>
#include <qsmtpd/userconf.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* to satisfy the linker */
const char **globalconf;

int
err_control(const char *fn)
{
	fprintf(stderr, "%s(%s) called unexpected\n",
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
test_vpop(void)
{
	int errcnt = 0; /**< error count */
	unsigned int tvidx = 0;	/**< index in cdb_testvector */

	while (cdb_testvector[tvidx].value != NULL) {
		int r;
		struct userconf ds;

		userconf_init(&ds);
		/* first test: only get the directory */
		r = vget_dir(cdb_testvector[tvidx].key, &ds);
		userconf_free(&ds);
		if (r < 0) {
			puts("ERROR: vget_dir() did not find expected directory");
			puts(cdb_testvector[tvidx].key);
			errcnt++;
			tvidx++;
			continue;
		}

		tvidx++;
	}

	/* now do the negative checks */
	tvidx = 0;
	while (cdb_testvector[tvidx].key != NULL) {
		int r;
		struct userconf ds;

		if (cdb_testvector[tvidx].value != NULL) {
			tvidx++;
			continue;
		}

		userconf_init(&ds);

		r = vget_dir(cdb_testvector[tvidx].key, &ds);
		if (r > 0) {
			puts("ERROR: vget_dir() returned success on entry that should not exist");
			puts(cdb_testvector[tvidx].key);
			if (ds.domainpath.s != NULL)
				puts(ds.domainpath.s);
			errcnt++;
		}
		userconf_free(&ds);

		tvidx++;
	}

	return errcnt;
}

int
main(int argc, char **argv)
{
	int err;
	struct userconf ds;
	char cdbtestdir[18];
	int fd;
	char too_long_domain[512];

	memset(too_long_domain, 'a', sizeof(too_long_domain) - 1);
	too_long_domain[sizeof(too_long_domain) - 1] = '\0';

	userconf_init(&ds);
	if (argc != 2) {
		puts("ERROR: parameter needs to be the name of the fake control directory");
		return EINVAL;
	}

	strncpy(cdbtestdir, "./cdbtest_XXXXXX", sizeof(cdbtestdir));
	if (mkdtemp(cdbtestdir) == NULL) {
		fputs("ERROR: can not create temporary directory for CDB test\n", stderr);
		return EINVAL;
	}
	if (chdir(cdbtestdir) != 0) {
		err = errno;
		fputs("ERROR: can not chdir to temporary directory\n", stderr);
		rmdir(cdbtestdir);
		return err;
	}
	if (mkdir("users", 0700) != 0) {
		err = errno;
		fputs("ERROR: can not create temporary directory for CDB test\n", stderr);
		if (chdir("..") == 0)
			rmdir(cdbtestdir);
		return err;
	}
	err = 0;
	fd = vget_dir("example.net", &ds);
	if (fd != 0) {
		fprintf(stderr, "searching for example.net in not existing users/cdb did not return 0, but %i\n", fd);
		err++;
	}
	fd = vget_dir(too_long_domain, &ds);
	if (fd != -EFAULT) {
		fputs("searching for too long domain name did not fail with the expected error code\n", stderr);
		err++;
	}
	fd = creat("users/cdb", 0600);
	if (fd == -1) {
		err = errno;
		fputs("ERROR: can not create temporary file for CDB test\n", stderr);
		rmdir("users");
		if (chdir("..") == 0)
			rmdir(cdbtestdir);
		return err;
	}
	close(fd);

	if (vget_dir("example.net", &ds) != 0) {
		fputs("searching for example.net in an empty users/cdb did not work as expected\n", stderr);
		err++;
	}
	unlink("users/cdb");
	rmdir("users");
	if (chdir("..") == 0)
		rmdir(cdbtestdir);

	if (chdir(argv[1]) != 0) {
		puts("ERROR: can not chdir to given directory");
		return EINVAL;
	}

	err += test_vpop();

	return err;
}
