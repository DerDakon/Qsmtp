#include "testcase_io.h"
#include "testcase_io_p.h"

#include <netio.h>

#include <string.h>

char linein[1002];
size_t linelen;

int
net_read(void)
{
	ASSERT_CALLBACK(testcase_net_read);

	return testcase_net_read();
}

int
tc_ignore_net_read(void)
{
	return 0;
}

int
net_writen(const char *const *a)
{
	ASSERT_CALLBACK(testcase_net_writen);

	return testcase_net_writen(a);
}

int
tc_ignore_net_writen(const char *const *a __attribute__((unused)))
{
	return 0;
}

int
tc_ignore_netwrite(const char *a __attribute__((unused)))
{
	return 0;
}

int
netnwrite(const char *a, const size_t len)
{
	ASSERT_CALLBACK(testcase_netnwrite);

	return testcase_netnwrite(a, len);
}

int
tc_ignore_netnwrite(const char *a __attribute__((unused)), const size_t len __attribute__((unused)))
{
	return 0;
}

size_t
net_readbin(size_t a, char *b)
{
	ASSERT_CALLBACK(testcase_net_readbin);

	return testcase_net_readbin(a, b);
}

size_t
tc_ignore_net_readbin(size_t a __attribute__((unused)), char *b __attribute__((unused)))
{
	return 0;
}

size_t
net_readline(size_t a, char *b)
{
	ASSERT_CALLBACK(testcase_net_readline);

	return testcase_net_readline(a, b);
}

size_t
tc_ignore_net_readline(size_t a __attribute__((unused)), char *b __attribute__((unused)))
{
	return 0;
}

int
data_pending(void)
{
	ASSERT_CALLBACK(testcase_data_pending);

	return testcase_data_pending();
}

int
tc_ignore_data_pending(void)
{
	return 0;
}

void
net_conn_shutdown(const enum conn_shutdown_type sd_type)
{
	if (testcase_net_conn_shutdown != NULL)
		testcase_net_conn_shutdown(sd_type);

	exit(0);
}

void
tc_ignore_net_conn_shutdown(const enum conn_shutdown_type sd_type __attribute__ ((unused)))
{
}

time_t timeout;
int socketd;

#ifdef DEBUG_IO
int do_debug_io;
int in_data;
#endif
