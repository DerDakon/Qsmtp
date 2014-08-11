#include "testcase_io.h"
#include "testcase_io_p.h"

#include <log.h>

#include <stdlib.h>

const char *log_write_msg;
int log_write_priority;

void
log_writen(int priority, const char **s)
{
	ASSERT_CALLBACK(testcase_log_writen);

	testcase_log_writen(priority, s);
}

void
tc_ignore_log_writen(int priority __attribute__((unused)), const char **s __attribute__((unused)))
{
}

void
testcase_log_writen_combine(int priority, const char **msg)
{
	size_t len = 0;
	unsigned int i;

	for (i = 0; msg[i] != NULL; i++)
		len += strlen(msg[i]);

	{
		char buf[len + 1];

		buf[0] = '\0';

		for (i = 0; msg[i] != NULL; i++)
			strcat(buf, msg[i]);

		log_write(priority, buf);
	}
}

void
testcase_log_writen_console(int priority, const char **msg)
{
	unsigned int i;

	printf("LOG OUTPUT[%i]: ", priority);

	for (i = 0; msg[i] != NULL; i++)
		printf("%s", msg[i]);

	printf("\n");
}

void
log_write(int priority, const char *s)
{
	const char *msg[] = { s, NULL };
	if (testcase_log_write == NULL)
		testcase_log_writen(priority, msg);
	else
		testcase_log_write(priority, s);
}

void
tc_ignore_log_write(int priority __attribute__((unused)), const char *s __attribute__((unused)))
{
}

void
testcase_log_write_compare(int priority, const char *a)
{
	if (log_write_msg == NULL) {
		fprintf(stderr, "log_write(%i, '%s') was called, but no message was expected)\n",
				priority, a);
		qs_backtrace();
		abort();
	}

	if (strcmp(log_write_msg, a) != 0) {
		fprintf(stderr, "log_write(%i, '%s') was called, but message '%s' was expected\n",
				priority, a, log_write_msg);
		qs_backtrace();
		abort();
	}

	if (priority != log_write_priority) {
		fprintf(stderr, "log_write(%i, '%s') was called, but priority %i was expected\n",
				priority, a, log_write_priority);
		qs_backtrace();
		abort();
	}

	log_write_msg = NULL;
}

void
dieerror(int error)
{
	ASSERT_CALLBACK(testcase_dieerror);

	testcase_dieerror(error);
	exit(error);
}

void
tc_ignore_dieerror(int error __attribute__((unused)))
{
}
