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

int main(void)
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

	return error;
}

void log_writen(int priority __attribute__ ((unused)), const char **msg __attribute__ ((unused)))
{
}

inline void log_write(int priority __attribute__ ((unused)), const char *msg __attribute__ ((unused)))
{
}
