#include <qremote/greeting.h>

#include <netio.h>
#include <qremote/qremote.h>
#include <sstring.h>
#include "test_io/testcase_io.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

struct string heloname;
char *rhost = "remote.host.name";

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
		"SIZEX",
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

	for (unsigned int i = 0; lines[i] != NULL; i++)
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
		int extension;
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

	for (unsigned int i = 0; lines[i].line != NULL; i++)
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

	for (unsigned int i = 0; lines[i].line != NULL; i++) {
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
		"AUTH \tPLAIN", /* unprintable character */
		NULL
	};
	int ret = 0;

	for (unsigned int i = 0; lines[i] != NULL; i++)
		if (esmtp_check_extension(lines[i]) != -1) {
			fprintf(stderr, "line '%s' not detected as invalid\n",
				lines[i]);
			ret++;
		}

	return ret;
}

static int
testcase_auth(void)
{
	struct {
		const char *line;
		const char *mechs;
	} lines[] = {
		{
			.line = "AUTH ",
			.mechs = NULL
		},
		{
			.line = "AUTH LOGIN PLAIN",
			.mechs = " LOGIN PLAIN "
		},
		{
			.line = "AUTH  LOGIN PLAIN",
			.mechs = " LOGIN PLAIN "
		},
		{
			.line = NULL
		}
	};
	int ret = 0;

	for (unsigned int i = 0; lines[i].line != NULL; i++) {
		remotesize = 42;

		if (esmtp_check_extension(lines[i].line) != esmtp_auth) {
			fprintf(stderr, "line '%s' not detected as correct AUTH line\n",
				lines[i].line);
			ret++;
			continue;
		}

		if ((lines[i].mechs == NULL) && (auth_mechs == NULL))
			/* fine, go on. */
			continue;

		if ((lines[i].mechs != NULL) && (auth_mechs != NULL) &&
				(strcmp(lines[i].mechs, auth_mechs) == 0))
			continue;

		fprintf(stderr, "line '%s' parsed mechanisms '%s', but expected '%s'\n",
				lines[i].line, auth_mechs, lines[i].mechs);
		ret++;
	}

	return ret;
}

#define MAX_NETGET 3
static struct {
	int ret;
	const char *line;
} netget_results[MAX_NETGET];

int
netget(const unsigned int terminate)
{
	if (netget_results[0].line == NULL) {
		fprintf(stderr, "unexpected call to %s(%u)\n", __func__, terminate);
		abort();
	}

	strncpy(linein.s, netget_results[0].line, TESTIO_MAX_LINELEN);
	linein.len = strlen(linein.s);
	int r  = netget_results[0].ret;

	for (int i = 0; i < MAX_NETGET - 1; i++)
		netget_results[i] = netget_results[i + 1];
	netget_results[MAX_NETGET - 1].line = NULL;

	return r;
}

static unsigned int nw_flags;
static const char helonm[] = "HELONAME";

int
test_net_writen(const char *const *msg)
{
	if (nw_flags & 2) {
		nw_flags ^= 2;
		if (strcmp(msg[0], "EHLO ") != 0) {
			fprintf(stderr, "first argument to net_writen() was '%s', but expected 'EHLO '\n",
					msg[0]);
			abort();
		}
	} else {
		assert(nw_flags == 1);
		nw_flags = 0;
		if (strcmp(msg[0], "HELO ") != 0) {
			fprintf(stderr, "first argument to net_writen() was '%s', but expected 'HELO '\n",
				msg[0]);
			abort();
		}
	}

	/* yes, pointer compare */
	if (msg[1] != helonm) {
		fprintf(stderr, "second argument to net_writen() was '%s', but expected '%s'\n",
			msg[1], helonm);
		abort();
	}

	if (msg[2] != NULL) {
		fprintf(stderr, "third argument to net_writen() was '%s', but expected NULL\n",
			msg[2]);
		abort();
	}

	return 0;
}

static int
check_calls(int gresult)
{
	int ret = greeting();

	if (ret != gresult) {
		fprintf(stderr, "%s: greeting() returned %i instead of %i\n",
			__func__, ret, gresult);
		ret = 1;
	} else {
		ret = 0;
	}

	if (netget_results[0].line != NULL) {
		fprintf(stderr, "%s: greeting() did not call netget() often enough\n",
			__func__);
		ret++;
	}

	if (nw_flags != 0) {
		fprintf(stderr, "%s: greeting() did not call net_writen() often enough\n",
			__func__);
		ret++;
	}

	return ret;
}

static int
test_greeting_helo(void)
{
	nw_flags = 3;

	netget_results[0].line = "503 5.5.1 Bad sequence of commands";
	netget_results[0].ret = 503;
	netget_results[1].line = "250 nice to meet you";
	netget_results[1].ret = 250;

	return check_calls(0);
}

static int
test_greeting_ehlo(void)
{
	nw_flags = 2;

	netget_results[0].line = "250-nice to meet you";
	netget_results[0].ret = 250;
	netget_results[1].line = "250 X-FOO";
	netget_results[1].ret = 250;

	return check_calls(0);
}

static int
test_greeting_helo_fail(void)
{
	nw_flags = 3;

	netget_results[0].line = "503 5.5.1 Bad sequence of commands";
	netget_results[0].ret = 503;
	netget_results[1].line = "503 5.5.1 Bad sequence of commands";
	netget_results[1].ret = 503;

	return check_calls(-EDONE);
}

static int
test_greeting_helo_mixed(void)
{
	nw_flags = 3;

	netget_results[0].line = "503 5.5.1 Bad sequence of commands";
	netget_results[0].ret = 503;
	netget_results[1].line = "251-nice to meet you";
	netget_results[1].ret = 251;
	netget_results[2].line = "250 X-FOO";
	netget_results[2].ret = 250;

	return check_calls(-EINVAL);
}

static int
test_greeting_ehlo_mixed(void)
{
	nw_flags = 2;

	netget_results[0].line = "251-nice to meet you";
	netget_results[0].ret = 251;
	netget_results[1].line = "250 X-FOO";
	netget_results[1].ret = 250;

	return check_calls(-EINVAL);
}

static int
test_greeting_ehlo_multi(void)
{
	nw_flags = 2;

	netget_results[0].line = "250-nice to meet you";
	netget_results[0].ret = 250;
	netget_results[1].line = "250-SIZE 42";
	netget_results[1].ret = 250;
	netget_results[2].line = "250 STARTTLS";
	netget_results[2].ret = 250;

	remotesize = 0;

	int r = check_calls(esmtp_size | esmtp_starttls);

	if (remotesize != 42) {
		fprintf(stderr, "%s: remotesize is %lu, but it should be 42\n",
				__func__, remotesize);
		r++;
	}

	remotesize = 0;

	return r;
}

/**
 * @brief testcase to check that the first line is not parsed for ESMTP extensions
 */
static int
test_greeting_ehlo_skip_first_line(void)
{
	nw_flags = 2;

	netget_results[0].line = "250-STARTTLS";
	netget_results[0].ret = 250;
	netget_results[1].line = "250 SIZE 42";
	netget_results[1].ret = 250;

	remotesize = 0;

	int r = check_calls(esmtp_size);

	if (remotesize != 42) {
		fprintf(stderr, "%s: remotesize is %lu, but it should be 42\n",
				__func__, remotesize);
		r++;
	}

	remotesize = 0;

	return r;
}

static int
test_greeting_ehlo_invalid(void)
{
	const char badmsg[] = "syntax error in EHLO response \"250-SIZE JUNK\" from ";
	char logbuf[strlen(badmsg) + strlen(rhost) + 1];

	strcpy(logbuf, badmsg);
	strcat(logbuf, rhost);
	log_write_priority = LOG_WARNING;
	log_write_msg = logbuf;

	nw_flags = 2;

	netget_results[0].line = "250-nice to meet you";
	netget_results[0].ret = 250;
	netget_results[1].line = "250-SIZE JUNK";
	netget_results[1].ret = 250;
	netget_results[2].line = "250 STARTTLS";
	netget_results[2].ret = 250;

	remotesize = 0;

	testcase_setup_log_writen(testcase_log_writen_combine);
	testcase_setup_log_write(testcase_log_write_compare);

	int r = check_calls(-EINVAL);

	if (remotesize != 0) {
		fprintf(stderr, "%s: remotesize is %lu, but it should be 0\n",
			__func__, remotesize);
		r++;
		remotesize = 0;
	}

	return r;
}

static int
test_greeting_helo_invalid_code(void)
{
	nw_flags = 3;

	netget_results[0].line = "503 5.5.1 Bad sequence of commands";
	netget_results[0].ret = 503;
	netget_results[1].line = "300 stuff";
	netget_results[1].ret = 300;

	return check_calls(-EINVAL);
}

static int
test_greeting_ehlo_syntax_first(void)
{
	const char badmsg[] = "syntax error in EHLO response \"junk\" from ";
	char logbuf[strlen(badmsg) + strlen(rhost) + 1];

	strcpy(logbuf, badmsg);
	strcat(logbuf, rhost);
	log_write_priority = LOG_WARNING;
	log_write_msg = logbuf;

	nw_flags = 2;

	netget_results[0].line = "junk";
	netget_results[0].ret = -EINVAL;

	return check_calls(-EINVAL);
}

static int
test_greeting_ehlo_syntax_second(void)
{
	const char badmsg[] = "syntax error in EHLO response \"junk\" from ";
	char logbuf[strlen(badmsg) + strlen(rhost) + 1];

	strcpy(logbuf, badmsg);
	strcat(logbuf, rhost);
	log_write_priority = LOG_WARNING;
	log_write_msg = logbuf;

	nw_flags = 2;

	netget_results[0].line = "250-nice to meet you";
	netget_results[0].ret = 250;
	netget_results[1].line = "junk";
	netget_results[1].ret = -EINVAL;

	return check_calls(-EINVAL);
}

static int
test_greeting_helo_syntax_first(void)
{
	const char badmsg[] = "syntax error in HELO response \"junk\" from ";
	char logbuf[strlen(badmsg) + strlen(rhost) + 1];

	strcpy(logbuf, badmsg);
	strcat(logbuf, rhost);
	log_write_priority = LOG_WARNING;
	log_write_msg = logbuf;

	nw_flags = 3;

	netget_results[0].line = "503 5.5.1 Bad sequence of commands";
	netget_results[0].ret = 503;
	netget_results[1].line = "junk";
	netget_results[1].ret = -EINVAL;

	return check_calls(-EINVAL);
}

static int
test_greeting_helo_syntax_second(void)
{
	const char badmsg[] = "syntax error in HELO response \"junk\" from ";
	char logbuf[strlen(badmsg) + strlen(rhost) + 1];

	strcpy(logbuf, badmsg);
	strcat(logbuf, rhost);
	log_write_priority = LOG_WARNING;
	log_write_msg = logbuf;

	nw_flags = 3;

	netget_results[0].line = "503 5.5.1 Bad sequence of commands";
	netget_results[0].ret = 503;
	netget_results[1].line = "250-nice to meet you";
	netget_results[1].ret = 250;
	netget_results[2].line = "junk";
	netget_results[2].ret = -EINVAL;

	return check_calls(-EINVAL);
}

int
main(void)
{
	int ret = 0;

	ret += testcase_ignore();
	ret += testcase_no_args();
	ret += testcase_size();
	ret += testcase_invalid();
	ret += testcase_auth();

	heloname.s = (char *)helonm;
	heloname.len = strlen(heloname.s);

	testcase_setup_net_writen(test_net_writen);

	ret += test_greeting_helo();
	ret += test_greeting_ehlo();
	ret += test_greeting_helo_fail();
	ret += test_greeting_helo_mixed();
	ret += test_greeting_ehlo_mixed();
	ret += test_greeting_ehlo_multi();
	ret += test_greeting_ehlo_invalid();
	ret += test_greeting_ehlo_skip_first_line();
	ret += test_greeting_helo_invalid_code();
	ret += test_greeting_ehlo_syntax_first();
	ret += test_greeting_ehlo_syntax_second();
	ret += test_greeting_helo_syntax_first();
	ret += test_greeting_helo_syntax_second();

	return ret;
}
