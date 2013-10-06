#define _ISOC99_SOURCE
#ifndef CHUNKING
#define CHUNKING
#endif /* CHUNKING */

#include "netio.h"
#include "qrdata.h"
#include "qremote.h"
#include "test_io/testcase_io.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

unsigned int may_log_count;

string heloname;
unsigned int smtpext;

const char *msgdata;
off_t msgsize;
char *outbuf;
size_t outlen;
size_t outpos;

#ifdef DEBUG_IO
int in_data;
#endif /* DEBUG_IO */

void
quit(void)
{
	fprintf(stderr, "%s() called unexpected\n", __FUNCTION__);
	exit(EFAULT);
}

static const char **checkreply_msgs;
static unsigned int checkreply_index;

int
checkreply(const char *status, const char **pre __attribute__ ((unused)), const int mask __attribute__ ((unused)))
{
	if ((checkreply_msgs == NULL) || (checkreply_msgs[checkreply_index] == NULL)) {
		fprintf(stderr, "%s was called but should not, status '%s'\n", __FUNCTION__, status);
		exit(EFAULT);
	}

	if (strcmp(status, checkreply_msgs[checkreply_index]) != 0) {
		fprintf(stderr, "expected message at index %u not received, got '%s', expected '%s'\n",
			checkreply_index, status, checkreply_msgs[checkreply_index]);
		exit(EINVAL);
	}

	checkreply_index++;
	return 250;
}

static unsigned int was_send_data_called;

void
send_data(unsigned int recodeflag)
{
	if (recodeflag != 42) {
		fprintf(stderr, "invalid recodeflag %u found\n", recodeflag);
		exit(EINVAL);
	}

	was_send_data_called = 1;
}

void
test_log_write(int priority, const char *s)
{
	if (may_log_count > 0) {
		may_log_count--;
		return;
	}
	fprintf(stderr, "log_write(%i, %s) called unexpected\n", priority, s);
	exit(EFAULT);

}

void
test_net_conn_shutdown(const enum conn_shutdown_type sdtype __attribute__((unused)))
{
	free(outbuf);
	outbuf = NULL;
}

const char *successmsg[] = {"1", "2", "3", "4", "5", "6", "7", NULL};

static const char **write_msgs;
static unsigned int write_msg_index;

int
test_netnwrite(const char *s, const size_t l)
{
	if ((write_msgs == NULL) || (write_msgs[write_msg_index] == NULL)) {
		fprintf(stderr, "unexpected message with index %u: len %zu, '%s'\n",
				write_msg_index, l, s);
		exit(EINVAL);
	}

	if (strlen(write_msgs[write_msg_index]) != l) {
		fprintf(stderr, "got message with length %zu at index %u, but expected length %zu\n",
				l, write_msg_index, strlen(write_msgs[write_msg_index]));
		exit(EINVAL);
	}

	if (strncmp(s, write_msgs[write_msg_index], l) != 0) {
		fprintf(stderr, "expected message at index %u not received\n",
				write_msg_index);
		exit(EINVAL);
	}

	write_msg_index++;

	return 0;
}
static int
test_bad_malloc(void)
{
	may_log_count = 1;
	chunksize = (size_t)-1;
	checkreply_msgs = NULL;
	successmsg[2] = "3";

	testcase_setup_log_write(test_log_write);

	msgdata = "1234\r\n.\r\n";
	msgsize = strchr(msgdata, '\n') - msgdata + 1;

	send_bdat(42);

	if (may_log_count != 0) {
		fprintf(stderr, "may_log_count is %i but should be 0\n", may_log_count);
		return 1;
	}

	if (was_send_data_called != 1) {
		fprintf(stderr, "send_data() should have been called once, but was called %u times\n", was_send_data_called);
		return 1;
	}

	if (strcmp(successmsg[2], "3") != 0) {
		fprintf(stderr, "successmsg[2] should have been '3', but is '%s'\n", successmsg[2]);
		return 1;
	}

	return 0;
}

static int
test_single_byte(void)
{
	const char *netmsgs[] = {
		"BDAT 1 LAST\r\na",
		NULL
	};
	const char *chrmsgs[] = {
		"KZD",
		NULL
	};

	msgdata = "a";
	msgsize = strlen(msgdata);
	may_log_count = 0;
	chunksize = 1024;
	write_msg_index = 0;
	write_msgs = netmsgs;
	checkreply_index = 0;
	checkreply_msgs = chrmsgs;
	successmsg[2] = "3";

	testcase_setup_netnwrite(test_netnwrite);

	send_bdat(0);

	if (strcmp(successmsg[2], "chunked ") != 0) {
		fprintf(stderr, "successmsg[2] should have been 'chunked ', but is '%s'\n", successmsg[2]);
		return 1;
	}

	return 0;
}

static int
test_wrap_single_line(void)
{
	const char *netmsgs[] = {
		"BDAT 3\r\nabc",
		"BDAT 3\r\ndef",
		"BDAT 2 LAST\r\ngh",
		NULL
	};
	const char *chrmsgs[] = {
		" ZD",
		" ZD",
		"KZD",
		NULL
	};

	msgdata = "abcdefgh";
	msgsize = strlen(msgdata);
	may_log_count = 0;
	chunksize = 18;
	write_msg_index = 0;
	write_msgs = netmsgs;
	checkreply_index = 0;
	checkreply_msgs = chrmsgs;
	successmsg[2] = "3";

	testcase_setup_netnwrite(test_netnwrite);

	send_bdat(0);

	if (strcmp(successmsg[2], "chunked ") != 0) {
		fprintf(stderr, "successmsg[2] should have been 'chunked ', but is '%s'\n", successmsg[2]);
		return 1;
	}

	return 0;
}

int
main(void)
{
	int ret = 0;

	ret += test_bad_malloc();
	ret += test_single_byte();
	ret += test_wrap_single_line();

	return ret;
}
