#include "greeting.h"
#include <stdio.h>

/**
 * @brief pass EHLO lines that should be ignored because they are unknown
 */
static int
testcase_ignore(void)
{
	const char *lines[] = {
		"X-FOO",
		"X-FOO WITH ARGS",
		"FOO",
		"FOO WITH ARGS",
		"SIZEX"
		"SIZEX WITH ARGS",
		"PIPELININGX",
		"PIPELININGX WITH ARGS",
		"STARTTLSX",
		"STARTTLSX WITH ARGS",
		"8BITMIMEX",
		"8BITMIMEX WITH ARGS",
		"CHUNKINGX",
		"CHUNKINGX WITH ARGS",
		"AUTHXX",
		"AUTHX WITH ARGS",
		"AUTH=LOGIN PLAIN",
		NULL
	};
	int ret = 0;
	unsigned int i;

	for (i = 0; lines[i] != NULL; i++)
		if (esmtp_check_extension(lines[i]) != 0) {
			fprintf(stderr, "line '%s' not ignored\n",
					lines[i]);
			ret++;
		}

	return ret;
}

/**
 * @brief check that argumentless extension announcements are detected
 */
static int
testcase_no_args(void)
{
	struct {
		const char *line;
		unsigned int extension;
	} lines[] = {
		{
			.line = "STARTTLS",
			.extension = esmtp_starttls
		},
		{
			.line = "8BITMIME",
			.extension = esmtp_8bitmime
		},
		{
			.line = "PIPELINING",
			.extension = esmtp_pipelining
		},
#ifdef CHUNKING
		{
			.line = "CHUNKING",
			.extension = esmtp_chunking
		},
#endif /* CHUNKING */
		{
			.line = NULL
		}
	};
	int ret = 0;
	unsigned int i;

	for (i = 0; lines[i].line != NULL; i++)
		if (esmtp_check_extension(lines[i].line) != lines[i].extension) {
			fprintf(stderr, "line '%s' not detected as the correct extension\n",
				lines[i].line);
			ret++;
		}

	return ret;
}

/**
 * @brief test the size extension
 *
 * This test covers only the valid cases, the invalid cases are tested by
 * testcase_invalid().
 */
static int
testcase_size(void)
{
	struct {
		const char *line;
		unsigned long parsedsize;
	} lines[] = {
		{
			.line = "SIZE",
			.parsedsize = 42 /* should remain untouched */
		},
		{
			.line = "SIZE 1024",
			.parsedsize = 1024
		},
		{
			.line = NULL
		}
	};
	int ret = 0;
	unsigned int i;

	for (i = 0; lines[i].line != NULL; i++) {
		remotesize = 42;

		if (esmtp_check_extension(lines[i].line) != esmtp_size) {
			fprintf(stderr, "line '%s' not detected as correct SIZE line\n",
				lines[i].line);
			ret++;
			continue;
		}

		if (lines[i].parsedsize != remotesize) {
			fprintf(stderr, "line '%s' parsed size %lu, but expected %lu\n",
				lines[i].line, remotesize, lines[i].parsedsize);
			ret++;
			continue;
		}
	}

	return ret;
}

static int
testcase_invalid(void)
{
	const char *lines[] = {
		"SIZE ", /* space but no following arguments */
		"SIZE 0x1a", /* size with hexadecimal number */
		"SIZE foo", /* size with string argument */
		"SIZE 1024 1024", /* size with 2 arguments */
		"PIPELINING X", /* PIPELINING does not accept arguments */
		"STARTTLS X", /* STARTTLS does not accept arguments */
		"8BITMIME X", /* 8BITMIME does not accept arguments */
#ifdef CHUNKING
		"CHUNKING X", /* CHUNKING does not accept arguments */
#endif /* CHUNKING */
		NULL
	};
	int ret = 0;
	unsigned int i;

	for (i = 0; lines[i] != NULL; i++)
		if (esmtp_check_extension(lines[i]) != -1) {
			fprintf(stderr, "line '%s' not detected as invalid\n",
				lines[i]);
			ret++;
		}

	return ret;
}

int
main(void)
{
	int ret = 0;

	ret += testcase_ignore();
	ret += testcase_no_args();
	ret += testcase_size();
	ret += testcase_invalid();

	return ret;
}
