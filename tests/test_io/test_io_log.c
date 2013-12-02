#include "testcase_io.h"
#include "testcase_io_p.h"

#include <log.h>

#include <stdlib.h>

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
log_write(int priority, const char *s)
{
	ASSERT_CALLBACK(testcase_log_write);

	testcase_log_write(priority, s);
}

void
tc_ignore_log_write(int priority __attribute__((unused)), const char *s __attribute__((unused)))
{
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
