#include "testcase_io.h"
#include "testcase_io_p.h"

#include <netio.h>

#include <assert.h>
#include <string.h>

char linein[1002];
size_t linelen;

int
net_read(void)
{
	assert(testcase_net_read != NULL);

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
	assert(testcase_net_writen != NULL);

	return testcase_net_writen(a);
}

int
tc_ignore_net_writen(const char *const *a __attribute__((unused)))
{
	return 0;
}

int
netwrite(const char *a)
{
	if (testcase_netwrite != NULL)
		return testcase_netwrite(a);
	else
		return netnwrite(a, strlen(a));
}

int
tc_ignore_netwrite(const char *a __attribute__((unused)))
{
	return 0;
}

int
netnwrite(const char *a, const size_t len)
{
	assert(testcase_netnwrite != NULL);

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
	assert(testcase_net_readbin != NULL);

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
	assert(testcase_net_readline != NULL);

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
	assert(testcase_data_pending != NULL);

	return testcase_data_pending();
}

int
tc_ignore_data_pending(void)
{
	return 0;
}

time_t timeout;
int socketd;

#ifdef DEBUG_IO
int do_debug_io;
int in_data;
#endif
