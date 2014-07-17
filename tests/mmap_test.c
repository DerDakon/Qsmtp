#include "mmap.h"
#include "test_io/testcase_io.h"

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
	int fd, fd2;
	off_t len;
	void *buf;
	const size_t cmplen = strlen(pattern1) + 1 + strlen(pattern2);
	ssize_t t, u;

	unlink(testfname);
	fd = creat(testfname, 0644);
	if (fd == -1) {
		fprintf(stderr, "can not open %s for writing\n", testfname);
		return 1;
	}

	/* include trailing 0 */
	t = write(fd, pattern1, strlen(pattern1) + 1);
	if (t != (ssize_t)(strlen(pattern1) + 1)) {
		fprintf(stderr, "error writing to test file, result %zi", t);
		close(fd);
		unlink(testfname);
		return 2;
	}

	/* no trailing 0 */
	u = write(fd, pattern2, strlen(pattern2));
	close(fd);

	if (u != (ssize_t)strlen(pattern2)) {
		fprintf(stderr, "error writing to test file, result %zi", u);
		unlink(testfname);
		return 3;
	}

	assert(t + u == (ssize_t)cmplen);

	/* mmap() on already closed fd, should fail */
	buf = mmap_fd(fd, &len);

	if (buf != NULL)
		return 4;

	fd = open(testfname, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		fprintf(stderr, "can not open %s for reading\n", testfname);
		return 5;
	}

	if (flock(fd, LOCK_EX) != 0) {
		fprintf(stderr, "can not get exclusive lock on %s\n", testfname);
		close(fd);
		return 16;
	}

	buf = mmap_name(testfname, &len, &fd2);
	if ((buf != NULL) || (errno != ENOLCK)) {
		fputs("mmap_name() on exlusively locked file did not fail with ENOLCK\n", stderr);
		close(fd);
		return 17;
	}
	flock(fd, LOCK_UN);

	buf = mmap_fd(fd, &len);
	if (buf == NULL) {
		fprintf(stderr, "mmap_fd() failed, error %i\n", errno);
		close(fd);
		return 6;
	}
	close(fd);

	if (len != (off_t)cmplen) {
		fprintf(stderr, "mmap_fd() should return length %zi, but returned %li\n", cmplen, (long)len);
		return 7;
	}

	if ((memcmp(buf, pattern1, strlen(pattern1) + 1) != 0) ||
			(memcmp(buf + strlen(pattern1) + 1, pattern2, strlen(pattern2)) != 0)) {
		fputs("buffer does not contain expected data\n", stderr);
		return 8;
	}

	munmap(buf, len);

	fd = -1;
	buf = mmap_name(testfname, &len, &fd);
	if (buf == NULL) {
		fprintf(stderr, "mmap_name() failed, error %i\n", errno);
		return 9;
	}

	if (fd < 0) {
		fprintf(stderr, "mmap_name() returned invalid fd\n");
		return 10;
	}
	close(fd);

	if (len != (off_t)cmplen) {
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

	fd = creat(testfname, 0644);
	if (fd == -1) {
		fprintf(stderr, "can not open %s for writing\n", testfname);
		return 13;
	}

	close(fd);

	fd = open(testfname, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		fprintf(stderr, "can not open %s for reading\n", testfname);
		return 14;
	}

	buf = mmap_fd(fd, &len);
	if ((buf != NULL) || (len != 0) || (errno != 0)) {
		fprintf(stderr, "mapping an empty file by fd was expected to return (buf, len, errno) = (NULL, 0, 0), but returned (%p, %lli, %i)\n",
				buf, (long long)len, errno);
		return 15;
	}
	close(fd);

	fd = -1;
	buf = mmap_name(testfname, &len, &fd);
	if ((buf != NULL) || (len != 0) || (errno != 0)) {
		fprintf(stderr, "mapping an empty file by name was expected to return (buf, len, errno) = (NULL, 0, 0), but returned (%p, %lli, %i)\n",
			buf, (long long)len, errno);
		return 16;
	}

	unlink(testfname);

	return 0;
}
