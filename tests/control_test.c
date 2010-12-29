/** \file control_test.c
 \brief control file testcases
 */
#include "control.h"
#include "log.h"

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
	"eof.example.org";

static const char *present[] = {
	"domain.example.com",
	"domain2.example.com",
	"whitespace.example.com",
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

/* the even ones should be fines, the odd ones are off */
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

static int
test_oneliner()
{
	unsigned int i;
	int err = 0;
	char *buf = NULL;

	puts("== Running tests for loadoneliner()");

	for (i = 0; onelines[i] != NULL; i++) {
		size_t len;
		int fd = open("oneliner_test", O_WRONLY | O_CREAT, 0600);
		if (fd == -1) {
			puts("ERROR: can not create temporary file for testcase");
			return 1;
		}
		write(fd, onelines[i], strlen(onelines[i]));
		close(fd);

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

	puts("== Running tests for lloadfilefd()");

	/* simulate permission denied */
	errno = EACCES;

	if (lloadfilefd(-1, &buf, 0) != (size_t)-1) {
		fputs("lloadfilefd(-1) did not fail\n", stderr);
		err++;
	}
	/* must work, buf should not be changed */
	free(buf);

	fd = open("emptyfile", O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd == -1) {
		fputs("Can not create temporary file\n", stderr);
		return err + 1;
	}
	close(fd);
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
	fd = close(fd);
	if ((fd != -1) || (errno != EBADF)) {
		fputs("lloadfilefd() did not close the passed file descriptor\n", stderr);
		err++;
	}
	unlink("emptyfile");
	if (buf != NULL) {
		fputs("lloadfilefd() with an empty file did not set the buf pointer to NULL\n", stderr);
		err++;
	}

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
		fd = open("control_int", O_WRONLY | O_CREAT | O_EXCL, 0644);
		if (fd == -1) {
			fputs("cannot create control test file\n", stderr);
			return err + 1;
		}
		if (write(fd, patterns[i].str, strlen(patterns[i].str)) != strlen(patterns[i].str)) {
			fputs("error writing to test file\n", stderr);
			close(fd);
			unlink("control_int");
			return err + 1;
		}
		close(fd);
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

	return err;
}

int
main(void)
{
	const char ctrl_testfile[] = "control_testfile";
	int i;
	int error = 0;
	int fd;

	puts("== Running tests for finddomainmm()");

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

	fd = open(ctrl_testfile, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd == -1) {
		puts("cannot create control test file");
		return -1;
	}

	write(fd, contents, strlen(contents));
	close(fd);

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

	unlink(ctrl_testfile);

	error += test_oneliner();
	error += test_lload();
	error += test_intload();

	return error;
}

void log_writen(int priority __attribute__ ((unused)), const char **msg __attribute__ ((unused)))
{
}

inline void log_write(int priority __attribute__ ((unused)), const char *msg __attribute__ ((unused)))
{
}
