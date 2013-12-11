#include "cdb.h"
#include <qsmtpd/vpop.h>
#include "test_io/testcase_io.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

static struct {
	const char *key;
	const char *value;
	const char *realdomain;
} cdb_testvector[] =  {
	{
		.key = "example.org",
		.value = "/var/vpopmail/domains/example.org",
		.realdomain = "example.org"
	},
	{
		.key = "example.com",
		.value = "/var/vpopmail/domains/example.com",
		.realdomain = "example.com"
	},
	{
		.key = "foo.example.org",
		.value = "/var/vpopmail/domains/foo.example.org",
		.realdomain = "foo.example.org"
	},
	{
		.key = "alias.example.org",
		.value = "/var/vpopmail/domains/foo.example.org",
		.realdomain = "foo.example.org"
	},
	{
		.key = "nonexistent.example.org",
		.value = NULL,
		.realdomain = NULL
	},
	{
		.key = NULL,
		.value = NULL,
		.realdomain = NULL
	}
};

int
err_control(const char *fn)
{
	fprintf(stderr, "%s(%s) called unexpected\n",
			__func__, fn);
	exit(1);
}

static int
test_cdb(void)
{
	int errcnt = 0; /**< error count */
	int fd;
	int err;
	unsigned int tvidx = 0;	/**< index in cdb_testvector */
	struct stat st;
	const char *cdb_buf;
	char *cdb_mmap;

	/* try to open the cdb file */
	fd = open("users/cdb", O_RDONLY);
	if (fd < 0) {
		err = -errno;
		return err;
	}

	if (fstat(fd, &st) < 0) {
		err = -errno;
		while ((close(fd) < 0) && (errno == EINTR));
		return err;
	}
	if (!st.st_size) {
		err = 0;
		while (close(fd) < 0) {
			if (errno != EINTR)
				err = -errno;
		}
		return err;
	}

	/* call cdb_seekmm() with invalid file descriptor */
	errno = 0;
	cdb_buf = cdb_seekmm(-1, "foo", strlen("foo"), &cdb_mmap, &st);
	if ((cdb_buf != NULL) || (errno == 0)) {
		err = errno;
		printf("ERROR: cdb_seekmm(-1, ...) returned %p and errno %i\n",
				cdb_buf, err);
		close(fd);
		return 1;
	}

	while (cdb_testvector[tvidx].key != NULL) {
		char cdb_key[260];
		size_t cdbkeylen;
		int newfd = dup(fd);
		if (newfd < 0) {
			puts("ERROR: can not duplicate file descriptor");
			return -1;
		}

		cdbkeylen = strlen(cdb_testvector[tvidx].key) + 2;
		cdb_key[0] = '!';
		memcpy(cdb_key + 1, cdb_testvector[tvidx].key, cdbkeylen - 2);
		cdb_key[cdbkeylen - 1] = '-';
		cdb_key[cdbkeylen] = '\0';

		/* search the cdb file for our requested domain */
		cdb_buf = cdb_seekmm(newfd, cdb_key, cdbkeylen, &cdb_mmap, &st);
		if (cdb_testvector[tvidx].value != NULL) {
			if (cdb_buf == NULL) {
				puts("ERROR: expected entry not found");
				puts(cdb_testvector[tvidx].key);
				errcnt++;
			}
		} else {
			if (cdb_buf != NULL) {
				puts("ERROR: unexpected entry found. key:");
				puts(cdb_testvector[tvidx].key);
				puts("value:");
				puts(cdb_buf);
				errcnt++;
			}
		}
		if (cdb_buf != NULL) {
			munmap(cdb_mmap, st.st_size);
		}
		tvidx++;
	}

	close(fd);

	return errcnt;
}

static int
test_vpop(void)
{
	int errcnt = 0; /**< error count */
	unsigned int tvidx = 0;	/**< index in cdb_testvector */

	while (cdb_testvector[tvidx].value != NULL) {
		int r;
		string domaindir;

		/* first test: only get the directory */
		STREMPTY(domaindir);
		r = vget_dir(cdb_testvector[tvidx].key, &domaindir);
		if (r < 0) {
			puts("ERROR: vget_dir() did not find expected directory");
			puts(cdb_testvector[tvidx].key);
			errcnt++;
			tvidx++;
			continue;
		}
		free(domaindir.s);

		tvidx++;
	}

	/* now do the negative checks */
	tvidx = 0;
	while (cdb_testvector[tvidx].key != NULL) {
		int r;
		string domaindir;

		if (cdb_testvector[tvidx].value != NULL) {
			tvidx++;
			continue;
		}

		STREMPTY(domaindir);
		r = vget_dir(cdb_testvector[tvidx].key, &domaindir);
		if (r > 0) {
			puts("ERROR: vget_dir() returned success on entry that should not exist");
			puts(cdb_testvector[tvidx].key);
			if (domaindir.s != NULL)
				puts(domaindir.s);
			free(domaindir.s);
			errcnt++;
		}

		tvidx++;
	}

	return errcnt;
}

int
main(int argc, char **argv)
{
	int err;
	string tmp;
	char cdbtestdir[18];
	int fd;

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
		chdir("..");
		rmdir(cdbtestdir);
		return err;
	}
	err = 0;
	fd = vget_dir("example.net", &tmp);
	if (fd != -ENOENT) {
		fputs("searching for example.net in not existing users/cdb did not fail with the expected error code\n", stderr);
		err++;
	}
	fd = open("users/cdb", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1) {
		err = errno;
		fputs("ERROR: can not create temporary file for CDB test\n", stderr);
		rmdir("users");
		chdir("..");
		rmdir(cdbtestdir);
		return err;
	}
	close(fd);

	if (vget_dir("example.net", &tmp) != 0) {
		fputs("searching for example.net in an empty users/cdb did work as expected\n", stderr);
		err++;
	}
	unlink("users/cdb");
	rmdir("users");
	chdir("..");
	rmdir(cdbtestdir);

	if (chdir(argv[1]) != 0) {
		puts("ERROR: can not chdir to given directory");
		return EINVAL;
	}

	err = test_cdb();
	if (err != 0) {
		puts("ERROR: errors in CDB test, aborting");
		return EFAULT;
	}

	err += test_vpop();

	return err;
}
