#include "mmap.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/mman.h>

static const char pattern1[] = "this is the first test pattern";
static const char pattern2[] = "this is the second test pattern";
static const char testfname[] = "mmap_testfile";

int
main(void)
{
	int fd;
	off_t len;
	void *buf;
	const size_t cmplen = strlen(pattern1) + 1 + strlen(pattern2);
	ssize_t t, u;

	unlink(testfname);
	fd = open(testfname, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (fd == -1) {
		fprintf(stderr, "can not open %s for writing\n", testfname);
		return 1;
	}

	/* include trailing 0 */
	t = write(fd, pattern1, strlen(pattern1) + 1);
	if (t != strlen(pattern1) + 1) {
		fprintf(stderr, "error writing to test file, result %zi", t);
		close(fd);
		unlink(testfname);
		return 2;
	}

	/* no trailing 0 */
	u = write(fd, pattern2, strlen(pattern2));
	close(fd);

	if (u != strlen(pattern2)) {
		fprintf(stderr, "error writing to test file, result %zi", u);
		unlink(testfname);
		return 3;
	}

	assert(t + u == cmplen);

	/* mmap() on already closed fd, should fail */
	buf = mmap_fd(fd, &len);

	if (buf != NULL)
		return 4;

	fd = open(testfname, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "can not open %s for reading\n", testfname);
		return 5;
	}

	buf = mmap_fd(fd, &len);
	if (buf == NULL) {
		fprintf(stderr, "mmap_fd() failed, error %i\n", errno);
		return 6;
	}

	if (len != cmplen) {
		fprintf(stderr, "mmap_fd() should return length %zi, but returned %li\n", cmplen, (long)len);
		return 7;
	}

	if ((memcmp(buf, pattern1, strlen(pattern1) + 1) != 0) ||
			(memcmp(buf + strlen(pattern1) + 1, pattern2, strlen(pattern2)) != 0)) {
		fputs("buffer does not contain expected data\n", stderr);
		return 8;
	}

	munmap(buf, len);

	buf = mmap_name(testfname, &len, &fd);
	if (buf == NULL) {
		fprintf(stderr, "mmap_name() failed, error %i\n", errno);
		return 9;
	}

	if (len != cmplen) {
		fprintf(stderr, "mmap_name() should return length %zi, but returned %li\n", cmplen, (long)len);
		return 10;
	}

	if ((memcmp(buf, pattern1, strlen(pattern1) + 1) != 0) ||
			(memcmp(buf + strlen(pattern1) + 1, pattern2, strlen(pattern2)) != 0)) {
		fputs("buffer does not contain expected data\n", stderr);
		return 11;
	}

	munmap(buf, len);
	flock(fd, LOCK_UN);
	unlink(testfname);

	buf = mmap_name("nonexistent", &len, &fd);
	if (buf != NULL) {
		fputs("mapping a nonexistent file did not fail, please check if your build directory is clean\n", stderr);
		return 12;
	}

	fd = open(testfname, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (fd == -1) {
		fprintf(stderr, "can not open %s for writing\n", testfname);
		return 13;
	}

	close(fd);

	fd = open(testfname, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "can not open %s for reading\n", testfname);
		return 14;
	}

	buf = mmap_fd(fd, &len);
	close(fd);
	unlink(testfname);
	if (buf != NULL) {
		fputs("mapping an empty file did not fail\n", stderr);
		return 15;
	}

	return 0;
}
