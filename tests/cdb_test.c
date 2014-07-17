#include "cdb_entries.h"

#include <cdb.h>

#include <assert.h>
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
		close(fd);
		return err;
	}
	if (!st.st_size) {
		err = 0;
		if (close(fd) < 0)
			err = -errno;
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

int
main(void)
{
	int err = 0;

	err = test_cdb();

	return err;
}
