/** \file control_test.c
 \brief control file testcases
 */
#include "control.h"
#include <stdlib.h>
#include <stdio.h>

static const char contents[] =
	"domain.example.com\n\n"
	"domain2.example.com\n\n"
	"#comment.example.com\n\n"
	"whitespace.example.com \n"
	"tab.example.org\t\n"
	"ts.example.com\t \t\n\n"
	"eof.example.org";

int main(void)
{
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

	int i;
	int error = 0;

	for (i = 0; present[i] != NULL; i++) {
		int search = finddomainmm(contents, sizeof(contents), present[i]);

		if (search != 1) {
			error++;
			puts("\t ERROR: present domain not found");
			puts(present[i]);
		}
	}

	for (i = 0; absent[i] != NULL; i++) {
		int search = finddomainmm(contents, sizeof(contents), absent[i]);

		if (search != 0) {
			error++;
			puts("\t ERROR: absent domain found");
		}
	}

	return error;
}
