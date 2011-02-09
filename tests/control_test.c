/** \file control_test.c
 \brief control file testcases
 */
#include "control.h"
#include "log.h"
#include "test_io/testcase_io.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char contents[] =
	"\t\t\n"
	"domain.example.com\n\n"
	"domain2.example.com\n  \n"
	"#comment.example.com\n\t \n"
	"whitespace.example.com \n"
	"tab.example.org\t\n"
	"ts.example.com\t \t\n\n"
	".foo.example.net\n"
	"eof.example.org";

static const char *present[] = {
	"domain.example.com",
	"domain2.example.com",
	"whitespace.example.com",
	"bar.foo.example.net",
	"tab.example.org",
	"ts.example.com",
	"eof.example.org",
	NULL
};

static const char *absent[] = {
	"comment.example.com",
	"domain.example.comm",
	"omain.example.com",
	"example.com",
	"com",
	"org",
	"or",
	NULL
};

/* the even ones should be fine, the odd ones are off */
static const char *onelines[] = {
	"oneline",
	"one\ntwo",
	"\noneline",
	"\noneline\ntwo",
	"oneline\n",
	"#ignore\nline\nline",
	"#ignore\nline\n",
	NULL
};

static unsigned int logcnt;

static void
createTestFile(const char * const name, const char * const value)
{
	int fd;

	fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		fputs("ERROR: can not create temporary file for testcase\n", stderr);
		exit(1);
	}
	if (write(fd, value, strlen(value)) != strlen(value)) {
		fputs("ERROR: writing value to test file did not work\n", stderr);
		close(fd);
		unlink(name);
	}
	close(fd);
}

static int
test_oneliner()
{
	unsigned int i;
	int err = 0;
	char ch;	/* dummy */
	char *buf = &ch;
	int fd;
	const char nocontent[] = "# comment\n\n";
	size_t len;

	puts("== Running tests for loadonelinerfd()");

	/* only test error cases here, the good case will be tested by
	 * loadoneliner() tests below. */
	errno = ENOENT;
	if (loadonelinerfd(-1, &buf) != (size_t)-1) {
		fputs("loadonelinerfd() for not existing file should return -1\n", stderr);
		err++;
	}
	if (buf != NULL) {
		fputs("loadonelinerfd() for not existing file should set the buffer to NULL\n", stderr);
		err++;
	}

	errno = EACCES;
	if (loadonelinerfd(-1, &buf) != (size_t)-1) {
		fputs("loadonelinerfd() for read protected file should return -1\n", stderr);
		err++;
	}

	createTestFile("oneliner_test", nocontent);

	fd = open("oneliner_test", O_RDONLY);
	len = loadonelinerfd(fd, &buf);
	if (len != (size_t)-1) {
		fputs("loadonelinerfd() for file without useful content should return -1\n", stderr);
		err++;
	}
	if (buf != NULL) {
		fputs("loadonelinerfd() for file without useful content should set the buffer to NULL\n", stderr);
		err++;
	}

	puts("== Running tests for loadoneliner()");

	len = loadoneliner("oneliner_test", &buf, 0);
	if (len != (size_t)-1) {
		fputs("loadoneliner() for file without useful content should return -1\n", stderr);
		err++;
	}
	if (buf != NULL) {
		fputs("loadoneliner() for file without useful content should set the buffer to NULL\n", stderr);
		err++;
	}
	unlink("oneliner_test");

	for (i = 0; onelines[i] != NULL; i++) {
		createTestFile("oneliner_test", onelines[i]);

		len = loadoneliner("oneliner_test", &buf, 0);
		if ((len == (size_t)-1) != (i & 1)) {
			puts("ERROR: loadoneliner() test failed:");
			puts(onelines[i]);
		} else {
			if (len != (size_t)-1)
				free(buf);
		}
		unlink("oneliner_test");
	}

	if ((loadoneliner("nonexistent", &buf, 0) != (size_t)-1) || (errno != ENOENT)) {
		fputs("loadoneliner() for nonexistent file should fail with ENOENT\n", stderr);
		err++;
	}

	return err;
}

static int
test_lload()
{
	int err = 0;
	char *buf = NULL;
	char ch; /* dummy */
	int fd;
	int i;
	size_t sz;
	const char comment[] = "# comment\n";

	puts("== Running tests for lloadfilefd()");

	/* simulate permission denied */
	errno = EACCES;

	if (lloadfilefd(-1, &buf, 0) != (size_t)-1) {
		fputs("lloadfilefd(-1) did not fail\n", stderr);
		err++;
	}
	/* must work, buf should not be changed */
	free(buf);

	createTestFile("emptyfile", "");

	fd = open("emptyfile", O_RDONLY);
	if (fd == -1) {
		fputs("Can not open temporary file for reading\n", stderr);
		return err + 1;
	}
	buf = &ch;
	if (lloadfilefd(fd, &buf, 0) != 0) {
		fputs("Opening an empty file did not return size 0\n", stderr);
		err++;
	}
	i = close(fd);
	if ((i != -1) || (errno != EBADF)) {
		fputs("lloadfilefd() did not close the passed file descriptor\n", stderr);
		err++;
	}
	unlink("emptyfile");
	if (buf != NULL) {
		fputs("lloadfilefd() with an empty file did not set the buf pointer to NULL\n", stderr);
		err++;
	}

	/* fd is already closed so locking must fail */
	if ((lloadfilefd(fd, &buf, 0) != -1) || (errno != ENOLCK)) {
		fputs("Trying to lock an already closed fd must fail\n", stderr);
		err++;
	}

	createTestFile("emptyfile", "\n\n\n\n");

	fd = open("emptyfile", O_RDONLY);
	if (fd == -1) {
		fputs("Can not open temporary file for reading\n", stderr);
		return err + 1;
	}
	buf = &ch;
	if (lloadfilefd(fd, &buf, 1) != 0) {
		fputs("reading a file with only newlines and striptab set to 1 did not return size 0\n", stderr);
		err++;
	}
	if (buf != NULL) {
		fputs("lloadfilefd() on a file with only newlines did not set the buf pointer to NULL\n", stderr);
		err++;
	}

	fd = open("emptyfile", O_RDONLY);
	if (fd == -1) {
		fputs("Can not open temporary file for reading\n", stderr);
		return err + 1;
	}
	buf = &ch;
	if (lloadfilefd(fd, &buf, 2) != 0) {
		fputs("reading a file with only newlines and striptab set to 2 did not return size 0\n", stderr);
		err++;
	}
	if (buf != NULL) {
		fputs("lloadfilefd() on a file with only newlines did not set the buf pointer to NULL\n", stderr);
		err++;
	}

	unlink("emptyfile");

	createTestFile("lloadfile_test", "a b");
	fd = open("lloadfile_test", O_RDONLY);
	if (fd == -1) {
		fputs("Can not open temporary file for reading\n", stderr);
		return err + 1;
	}

	buf = NULL;
	if ((lloadfilefd(fd, &buf, 2) != (size_t)-1) || (errno != EINVAL)) {
		free(buf);
		fputs("lloadfilefd() on a file with spaces in the middle of a line should fail with striptabs 2\n", stderr);
		err++;
	}
	unlink("lloadfile_test");

	createTestFile("lloadfile_test", comment);
	fd = open("lloadfile_test", O_RDONLY);
	if (fd == -1) {
		fputs("Can not open temporary file for reading\n", stderr);
		return err + 1;
	}

	buf = NULL;
	sz = lloadfilefd(fd, &buf, 0);
	if (sz != strlen(comment)) {
		fputs("lloadfilefd() with striptabs 0 did not return correct size\n", stderr);
		err++;
	} else if (memcmp(buf, comment, strlen(comment)) != 0) {
		fputs("lloadfilefd() with striptabs 0 did not return correct contents\n", stderr);
		err++;
	}
	free(buf);

	return err;
}

static int
test_intload()
{
	int err = 0;
	int fd;
	int i = 0;
	unsigned long tmp;

	static const struct {
		const char *str;
		unsigned long value;
	} patterns[] = {
		{
			.str = "42",
			.value = 42
		},
		{
			.str = "17\n",
			.value = 17
		},
		{
			.str = "1023 ",
			.value = 1023
		},
		{
			.str = "28\t \n",
			.value = 28
		},
		{
			.str = "4294967295\n",
			.value = 0xffffffff
		},
		{
			.str = "180987\n#com m ment\n\n",
			.value = 180987
		},
		{
			.str = NULL,
			.value = 0
		}
	};

	while (patterns[i].str != NULL) {
		createTestFile("control_int", patterns[i].str);

		fd = open("control_int", O_RDONLY);
		if (fd == -1) {
			fputs("cannot open control test file\n", stderr);
			return err + 1;
		}

		tmp = 4;
		if (loadintfd(fd, &tmp, 5) != 0) {
			fprintf(stderr, "error reading value from file, expected %lu\n", patterns[i].value);
			err++;
		}
		if (tmp != patterns[i].value) {
			fprintf(stderr, "expected value %lu, got %lu\n", patterns[i].value, tmp);
			err++;
		}
		fd = close(fd);
		if ((fd != -1) || (errno != EBADF)) {
			fputs("loadintfd() did not close the file descriptor\n", stderr);
			err++;
		}
		unlink("control_int");

		i++;
	}

	errno = ENOENT;
	tmp = 42;
	if (loadintfd(-1, &tmp, 17) != 0) {
		fputs("loadintfd() for non-existing file should not fail\n", stderr);
		err++;
	}
	if (tmp != 17) {
		fputs("loadintfd() for non-existing file should return default value\n", stderr);
		err++;
	}

	errno = EACCES;
	tmp = 42;
	if (loadintfd(-1, &tmp, 17) != -1) {
		fputs("loadintfd() for unaccessible file should fail\n", stderr);
		err++;
	}
	if (tmp != 42) {
		fputs("loadintfd() with error should not set default value\n", stderr);
		err++;
	}

	createTestFile("control_int", "xy\n");

	fd = open("control_int", O_RDONLY);
	if (fd == -1) {
		fputs("cannot open control test file\n", stderr);
		return err + 1;
	}
	tmp = 42;
	if ((loadintfd(fd, &tmp, 17) != -1) || (errno != EINVAL)) {
		fputs("loadintfd() should reject string values with -1\n", stderr);
		err++;
	}
	unlink("control_int");

	return err;
}

static int
checkfunc_accept(const char *s  __attribute__ ((unused)))
{
	return 0;
}

static int
checkfunc_reject(const char *s  __attribute__ ((unused)))
{
	return 1;
}

static int
checkfunc_accept_b(const char *s)
{
	return !!strcmp(s, "b");
}

static int
test_listload()
{
	char ch;	/* dummy */
	char *buf;
	char **bufa;
	int fd;
	int res;
	int err = 0;
	const char fname[] = "control_list";
	checkfunc callbacks[4];
	int i;

	puts("== Running tests for loadlistfd()");

	buf = &ch;
	bufa = &buf;

	errno = ENOENT;
	res = loadlistfd(-1, &buf, &bufa, NULL);
	if (res != 0) {
		fputs("loadlistfd() with a not existing file should succeed\n", stderr);
		err++;
	}
	if ((buf != NULL) || (bufa != NULL)) {
		fputs("loadlistfd() with a not existing file should set the pointers to NULL\n", stderr);
		if (buf != NULL)
			err++;
		if (bufa != NULL)
			err++;
	}

	errno = EACCES;
	res = loadlistfd(-1, &buf, &bufa, NULL);
	if (res != -1) {
		fputs("loadlistfd() with a read protected file should fail\n", stderr);
		err++;
	}

	createTestFile(fname, "a\nb\n#comment\n\nc\n");
	callbacks[0] = checkfunc_reject;
	callbacks[1] = checkfunc_accept;
	callbacks[2] = checkfunc_accept_b;
	callbacks[3] = NULL;

	for (i = 0; i <= 3; i++) {
		fd = open(fname, O_RDONLY);
		if (fd == -1) {
			fputs("cannot open control test file for reading\n", stderr);
			unlink(fname);
			return err + 1;
		}

		buf = &ch;
		bufa = &buf;
		logcnt = 0;
		res = loadlistfd(fd, &buf, &bufa, callbacks[i]);
		if (res != 0) {
			fprintf(stderr, "loadlistfd() returned %i\n", res);
			err++;
		}

		if (i == 0) {
			if (logcnt != 3) {
				fprintf(stderr, "loadlistfd() should have complained about 3 invalid entries, but logcnt is %i\n", logcnt);
				err++;
			}
			if ((buf != NULL) || (bufa != NULL)) {
				fputs("loadlistfd() should have set the pointers to NULL\n", stderr);
				if (buf != NULL)
					err++;
				if (bufa != NULL)
					err++;
			}
		} else if ((buf != NULL) && (bufa != NULL)) {
			unsigned int end;
			if (i == 2) {
				if (strcmp(bufa[0], "b") != 0) {
					fputs("loadlistfd() did not return \"b\" as first array entry\n", stderr);
					err++;
				}
				end = 1;
			} else {
				if (strcmp(bufa[0], "a") != 0) {
					fputs("loadlistfd() did not return \"a\" as first array entry\n", stderr);
					err++;
				}
				if (strcmp(bufa[1], "b") != 0) {
					fputs("loadlistfd() did not return \"b\" as second array entry\n", stderr);
					err++;
				}
				if (strcmp(bufa[2], "c") != 0) {
					fputs("loadlistfd() did not return \"c\" as third array entry\n", stderr);
					err++;
				}
				end = 3;
			}
			if (bufa[end] != NULL) {
				fputs("loadlistfd() did not return a NULL-terminated array\n", stderr);
				err++;
			}
		} else {
			fputs("loadlistfd() did not return data\n", stderr);
			if (buf == NULL)
				err++;
			if (bufa == NULL)
				err++;
		}

		free(buf);
		free(bufa);
	}

	return err;
}

void test_log_writen(int priority __attribute__ ((unused)), const char **msg __attribute__ ((unused)))
{
	logcnt++;
}

inline void test_log_write(int priority __attribute__ ((unused)), const char *msg __attribute__ ((unused)))
{
	logcnt++;
}

int
main(void)
{
	const char ctrl_testfile[] = "control_testfile";
	int i;
	int error = 0;
	int fd;

	testcase_setup_log_write(test_log_write);
	testcase_setup_log_writen(test_log_writen);

	puts("== Running tests for finddomainmm()");

	/* empty memory area should not match anything */
	if (finddomainmm(NULL, 1024, present[0]) != 0) {
		fputs("\t ERROR: match found in NULL buffer\n", stderr);
		error++;
	}

	for (i = 0; present[i] != NULL; i++) {
		int search = finddomainmm(contents, strlen(contents), present[i]);

		if (search != 1) {
			error++;
			puts("\t ERROR: present domain not found");
			puts(present[i]);
		}
	}

	for (i = 0; absent[i] != NULL; i++) {
		int search = finddomainmm(contents, strlen(contents), absent[i]);

		if (search != 0) {
			error++;
			puts("\t ERROR: absent domain found");
		}
	}

	puts("== Running tests for finddomainfd()");

	errno = ENOENT;
	if (finddomainfd(-1, present[0], 0) != 0) {
		fputs("finddomainfd() for not existing file should return 0\n", stderr);
		error++;
	}

	errno = EACCES;
	if (finddomainfd(-1, present[0], 0) != -1) {
		fputs("finddomainfd() for read protected file should return -1\n", stderr);
		error++;
	}

	createTestFile(ctrl_testfile, contents);

	fd = open(ctrl_testfile, O_RDONLY);
	if (fd == -1) {
		puts("cannot open control test file for reading");
		unlink(ctrl_testfile);
		return -1;
	}

	for (i = 0; present[i] != NULL; i++) {
		int search;

		search = finddomainfd(fd, present[i], 0);

		if (search != 1) {
			error++;
			puts("\t ERROR: present domain not found");
			puts(present[i]);
		}
	}

	for (i = 0; absent[i] != NULL; i++) {
		int search;

		fd = open(ctrl_testfile, O_RDONLY);
		if (fd == -1) {
			puts("cannot open control test file for reading");
			unlink(ctrl_testfile);
			return -1;
		}

		search = finddomainfd(fd, absent[i], 1);

		if (search != 0) {
			error++;
			puts("\t ERROR: absent domain found");
		}

		/* fd must have been closed already */
		search = close(fd);
		if (search != -1) {
			puts("file descriptor was not closed");
			error++;
		} else if (errno != EBADF) {
			puts("file descriptor closing gave strange error");
			error++;
		}
	}

	/* already closed fd, should give lock error */
	if ((finddomainfd(fd, present[i], 0) != -1) || (errno != ENOLCK)) {
		fputs("Trying to lock an already closed fd must fail\n", stderr);
		error++;
	}

	unlink(ctrl_testfile);

	error += test_oneliner();
	error += test_lload();
	error += test_intload();
	error += test_listload();

	return error;
}
