#define _ISOC99_SOURCE
#ifndef CHUNKING
#define CHUNKING
#endif /* CHUNKING */

#include <netio.h>
#include <qremote/qrdata.h>
#include <qremote/qremote.h>
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

static unsigned int expect_quit;
static const char **write_msgs;
static unsigned int write_msg_index;
static struct checkreply_data {
	const char *status;
	int result;
} const *checkreply_msgs;
static unsigned int checkreply_index;

void
quit(void)
{
	if (expect_quit) {
		if (may_log_count != 0) {
			fprintf(stderr, "%u expected log messages were not sent\n", may_log_count);
			exit(EINVAL);
		}

		if ((checkreply_msgs != NULL) && (checkreply_msgs[checkreply_index].status != NULL)) {
			fprintf(stderr, "not all calls to checkreply() were done\n");
			exit(EINVAL);
		}

		if ((write_msgs != NULL) && (write_msgs[write_msg_index] != NULL)) {
			fprintf(stderr, "not all calls to netnwrite() were done\n");
			exit(EINVAL);
		}

		exit(0);
	}

	fprintf(stderr, "%s() called unexpected\n", __FUNCTION__);
	exit(EFAULT);
}

int
checkreply(const char *status, const char **pre __attribute__ ((unused)), const int mask __attribute__ ((unused)))
{
	if ((checkreply_msgs == NULL) || (checkreply_msgs[checkreply_index].status == NULL)) {
		fprintf(stderr, "%s was called but should not, status '%s'\n", __FUNCTION__, status);
		exit(EFAULT);
	}

	if (strcmp(status, checkreply_msgs[checkreply_index].status) != 0) {
		fprintf(stderr, "expected message at index %u not received, got '%s', expected '%s'\n",
			checkreply_index, status, checkreply_msgs[checkreply_index].status);
		exit(EINVAL);
	}

	return checkreply_msgs[checkreply_index++].result;
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

int
test_netnwrite_bdatlen(const char *s, const size_t l)
{
	unsigned long lp;
	size_t extralen;
	char *endptr;

	if (strncmp(s, "BDAT ", 5) != 0) {
		fprintf(stderr, "message %u does not start with BDAT command\n",
				write_msg_index);
		exit(EINVAL);
	}

	lp = strtoul(s + 5, &endptr, 10);

	if (strncmp(endptr, "\r\n", 2) == 0) {
		extralen = 2 + (endptr - s);
	} else if (strncmp(endptr, " LAST\r\n", 7) == 0) {
		extralen = 7 + (endptr - s);
	} else {
		fprintf(stderr, "can't parse message size declaration in message %u\n",
				write_msg_index);
		exit(EINVAL);
	}

	if (lp != l - extralen) {
		fprintf(stderr, "message %u announced %lu byte of data, but sent %zu\n",
				write_msg_index, lp, l - extralen);
		exit(EINVAL);
	}

	return 0;
}

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

	test_netnwrite_bdatlen(s, l);
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
	const struct checkreply_data chrmsgs[] = {
		{ "KZD", 250 },
		{ NULL, 0 }
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
	const struct checkreply_data chrmsgs[] = {
		{ " ZD", 250 },
		{ " ZD", 250 },
		{ "KZD", 250 },
		{ NULL, 0 }
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

static int
test_wrap_multi_lines(void)
{
	const char *netmsgs[] = {
		"BDAT 7\r\nab\r\ncde",
		"BDAT 7 LAST\r\n\r\nfgh\r\n",
		NULL
	};
	const struct checkreply_data chrmsgs[] = {
		{ " ZD", 250 },
		{ "KZD", 250 },
		{ NULL, 0 }
	};

	msgdata = "ab\r\ncde\r\nfgh\r\n";
	msgsize = strlen(msgdata);
	may_log_count = 0;
	chunksize = 22;
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
test_newline_crlf_errors(void)
{
	const char *netmsgs[] = {
		"BDAT 4\r\n\r\n\r\n",
		"BDAT 4\r\n\r\n\r\n",
		"BDAT 2 LAST\r\n\r\n",
		NULL
	};
	const struct checkreply_data chrmsgs[] = {
		{ " ZD", 250 },
		{ " ZD", 250 },
		{ "KZD", 250 },
		{ NULL, 0 }
	};

	msgdata = "\r\n\n\n\r\n\r";
	msgsize = strlen(msgdata);
	may_log_count = 1;
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

	if (may_log_count != 0) {
		fprintf(stderr, "may_log_count is %i but should be 0\n", may_log_count);
		return 1;
	}

	return 0;
}

static int
test_wrap_fail(void)
{
	const char *netmsgs[] = {
		"BDAT 3\r\nabc",
		"BDAT 3\r\ndef",
		NULL
	};
	const struct checkreply_data chrmsgs[] = {
		{ " ZD", 250 },
		{ " ZD", 550 },
		{ NULL, 0 }
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
	expect_quit = 1;

	testcase_setup_netnwrite(test_netnwrite);

	send_bdat(0);

	fprintf(stderr, "end of %s reached, send_bdat() should not have returned\n", __FUNCTION__);
	return 1;
}

int
main(void)
{
	int ret = 0;

	ret += test_bad_malloc();
	ret += test_single_byte();
	ret += test_wrap_single_line();
	ret += test_wrap_multi_lines();
	ret += test_newline_crlf_errors();

	if (ret != 0) {
		fprintf(stderr, "%i errors before calling final test\n", ret);
		return ret;
	}

	return test_wrap_fail();
}
