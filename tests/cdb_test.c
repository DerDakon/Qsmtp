#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "cdb.h"
#include "vpop.h"

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
		char *realdomain = NULL;

		/* first test: only get the directory */
		STREMPTY(domaindir);
		r = vget_dir(cdb_testvector[tvidx].key, &domaindir, NULL);
		if (r < 0) {
			puts("ERROR: vget_dir() did not find expected directory");
			puts(cdb_testvector[tvidx].key);
			errcnt++;
			tvidx++;
			continue;
		}
		free(domaindir.s);

		/* second test: only get the real domain */
		r = vget_dir(cdb_testvector[tvidx].key, NULL, &realdomain);
		assert(r > 0);
		if (realdomain == NULL) {
			puts("ERROR: vget_dir() did not return realdomain");
			puts(cdb_testvector[tvidx].key);
			errcnt++;
			tvidx++;
			continue;
		} else {
			if (strcmp(realdomain, cdb_testvector[tvidx].realdomain) != 0) {
				puts("ERROR: vget_dir() did not return expected realdomain");
				puts(cdb_testvector[tvidx].key);
				puts(cdb_testvector[tvidx].realdomain);
				puts(realdomain);
				free(realdomain);
				errcnt++;
				tvidx++;
				continue;
			}
		}
		free(realdomain);

		/* third test: only get botj */
		STREMPTY(domaindir);
		realdomain = NULL;
		r = vget_dir(cdb_testvector[tvidx].key, &domaindir, &realdomain);
		assert(r > 0);

		free(realdomain);
		free(domaindir.s);

		tvidx++;
	}

	/* now do the negative checks */
	tvidx = 0;
	while (cdb_testvector[tvidx].key != NULL) {
		int r;
		string domaindir;
		char *realdomain;

		if (cdb_testvector[tvidx].value != NULL) {
			tvidx++;
			continue;
		}

		STREMPTY(domaindir);
		realdomain = NULL;
		r = vget_dir(cdb_testvector[tvidx].key, &domaindir, &realdomain);
		if (r > 0) {
			puts("ERROR: vget_dir() returned success on entry that should not exist");
			puts(cdb_testvector[tvidx].key);
			if (domaindir.s != NULL)
				puts(domaindir.s);
			if (realdomain != NULL)
				puts(realdomain);
			free(domaindir.s);
			free(realdomain);
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

	if (argc != 2) {
		puts("ERROR: parameter needs to be the name of the fake control directory");
		return EINVAL;
	}

	if (chdir(argv[1]) != 0) {
		puts("ERROR: can not chdir to given directory");
		return EINVAL;
	}

	err = test_cdb();
	if (err != 0) {
		puts("ERROR: errors in CDB test, aborting");
		return EFAULT;
	}

	test_vpop();

	return 0;
}
