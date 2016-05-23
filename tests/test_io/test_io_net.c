#include "testcase_io.h"
#include "testcase_io_p.h"

#include <netio.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static char lineinbuf[TESTIO_MAX_LINELEN];
struct string linein = {
	.s = lineinbuf
};
const char *netnwrite_msg;
const char **netnwrite_msg_next;
const char *net_read_msg;
const char **net_read_msg_next;
int net_read_fatal;

int
net_read(const int fatal)
{
	ASSERT_CALLBACK(testcase_net_read);

	return testcase_net_read(fatal);
}

int
testcase_net_read_simple(const int fatal)
{
	if (net_read_msg == NULL) {
		qs_backtrace();
		abort();
	}

	if ((fatal != 0) && (fatal != 1)) {
		qs_backtrace();
		abort();
	}

	if (net_read_fatal != fatal) {
		qs_backtrace();
		abort();
	}

	if ((uintptr_t)net_read_msg < 4096) {
		errno = (int)(uintptr_t)net_read_msg;
		net_read_msg = NULL;
		net_read_fatal = -1;
		return -1;
	}

	assert(strlen(net_read_msg) < sizeof(lineinbuf));

	strcpy(linein.s, net_read_msg);
	linein.len = strlen(net_read_msg);

	if (net_read_msg_next != NULL) {
		assert(*net_read_msg_next != NULL);
		net_read_msg = *net_read_msg_next++;
		if (*net_read_msg_next == NULL)
			net_read_msg_next = NULL;
	} else {
		net_read_msg = NULL;
		net_read_fatal = -1;
	}

	return 0;
}

int
tc_ignore_net_read(const int fatal __attribute__((unused)))
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
testcase_net_writen_combine(const char *const *msg)
{
	size_t len = 0;
	unsigned int i;

	for (i = 0; msg[i] != NULL; i++)
		len += strlen(msg[i]);

	{
		char buf[len + 3];

		memset(buf, 0, len + 1);

		for (i = 0; msg[i] != NULL; i++)
			strcat(buf, msg[i]);

		strcat(buf, "\r\n");

		netnwrite(buf, len + 2);
	}

	return 0;
}

int
net_write_multiline(const char *const *a)
{
	ASSERT_CALLBACK(testcase_net_write_multiline);

	return testcase_net_write_multiline(a);
}

int
tc_ignore_net_write_multiline(const char *const *a __attribute__((unused)))
{
	return 0;
}

int
testcase_native_net_write_multiline(const char *const *s)
{
	size_t len = 0;
	char *buf;
	int i;

	for (i = 0; s[i]; i++)
		len += strlen(s[i]);

	assert(i > 0);
	assert(len > 2);

	buf = malloc(len + 1);
	if (buf == NULL)
		abort();

	buf[0] = '\0';
	for (i = 0; s[i]; i++)
		strcat(buf, s[i]);

	assert(buf[len - 1] == '\n');
	assert(buf[len - 2] == '\r');

	i = netnwrite(buf, len);

	free(buf);

	return i;
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
testcase_netnwrite_compare(const char *a, const size_t len)
{
	if (netnwrite_msg == NULL) {
		fprintf(stderr, "netnwrite('%s', %zu) was called, but no message was expected)\n",
				a, len);
		qs_backtrace();
		abort();
	}

	if ((strncmp(netnwrite_msg, a, len) != 0) || (strlen(netnwrite_msg) != len)) {
		fprintf(stderr, "netnwrite('%s', %zu) was called, but message ('%s', %zu) was expected\n",
				a, len, netnwrite_msg, strlen(netnwrite_msg));
		qs_backtrace();
		abort();
	}

	if (netnwrite_msg_next != NULL) {
		assert(*netnwrite_msg_next != NULL);
		netnwrite_msg = *netnwrite_msg_next++;
		if (*netnwrite_msg_next == NULL)
			netnwrite_msg_next = NULL;
	} else {
		netnwrite_msg = NULL;
	}

	return 0;
}

int
testcase_netnwrite_check(const char *prefix)
{
	if (netnwrite_msg == NULL)
		return 0;

	assert(netnwrite_msg_next == NULL);
	fprintf(stderr, "%s: the expected network message '%s' was not sent\n", prefix, netnwrite_msg);
	netnwrite_msg = NULL;
	return 1;
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
int socketd = -1;

#ifdef DEBUG_IO
int do_debug_io;
int in_data;
#endif
