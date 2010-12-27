#include "netio.h"
#include "qrdata.h"
#include "qremote.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

enum datastate {
	ST_START,
	ST_DATA,
	ST_354,
	ST_DATAEND,
	ST_DATADONE,
	ST_FINISH
};

static enum datastate state = ST_START;

string heloname;
unsigned int smtpext;
char linein[4];
size_t linelen = 3;

char *outbuf;
size_t outlen;
size_t outpos;

#ifdef DEBUG_IO
int in_data;
#endif /* DEBUG_IO */

static struct {
	const char *name;
	const char *msg;
	unsigned int filters;
} testpatterns[] = {
	{
		.name = "simple",
		.msg = "Subject: simple test\r\n\r\n\r\n",
		.filters = 0
	},
	{
		.name = "crlfmixup",
		.msg = "Subject: CRLF test\r\r\n\n\r\n\n\r\r ",
		.filters = 0
	},
	{
		.name = "longBodyLine",
		.msg = "Subject: long body line\r\n\r\n"
				"   50 12345678901234567890123456789012345678901234"
				"  100 12345678901234567890123456789012345678901234"
				"  150 12345678901234567890123456789012345678901234"
				"  200 12345678901234567890123456789012345678901234"
				"  250 12345678901234567890123456789012345678901234"
				"  300 12345678901234567890123456789012345678901234"
				"  350 12345678901234567890123456789012345678901234"
				"  400 12345678901234567890123456789012345678901234"
				"  450 12345678901234567890123456789012345678901234"
				"  500 12345678901234567890123456789012345678901234"
				"  550 12345678901234567890123456789012345678901234"
				"  600 12345678901234567890123456789012345678901234"
				"  650 12345678901234567890123456789012345678901234"
				"  700 12345678901234567890123456789012345678901234"
				"  750 12345678901234567890123456789012345678901234"
				"  800 12345678901234567890123456789012345678901234"
				"  850 12345678901234567890123456789012345678901234"
				"  900 12345678901234567890123456789012345678901234"
				"  950 12345678901234567890123456789012345678901234"
				" 1000 12345678901234567890123456789012345678901234"
				" 1050 12345678901234567890123456789012345678901234\r\n",
		.filters = 0
	},
	{
		.name = "longHeaderLine",
		.msg = "Subject: long header line"
				"   50 12345678901234567890123456789012345678901234"
				"  100 12345678901234567890123456789012345678901234"
				"  150 12345678901234567890123456789012345678901234"
				"  200 12345678901234567890123456789012345678901234"
				"  250 12345678901234567890123456789012345678901234"
				"  300 12345678901234567890123456789012345678901234"
				"  350 12345678901234567890123456789012345678901234"
				"  400 12345678901234567890123456789012345678901234"
				"  450 12345678901234567890123456789012345678901234"
				"  500 12345678901234567890123456789012345678901234"
				"  550 12345678901234567890123456789012345678901234"
				"  600 12345678901234567890123456789012345678901234"
				"  650 12345678901234567890123456789012345678901234"
				"  700 12345678901234567890123456789012345678901234"
				"  750 12345678901234567890123456789012345678901234"
				"  800 12345678901234567890123456789012345678901234"
				"  850 12345678901234567890123456789012345678901234"
				"  900 12345678901234567890123456789012345678901234"
				"  950 12345678901234567890123456789012345678901234"
				" 1000 12345678901234567890123456789012345678901234"
				" 1050 12345678901234567890123456789012345678901234\r\n\r\n",
		.filters = 0
	},
	{
		.name = "emptyLFheader",
		.msg = "\ndata\r\n",
		.filters = 0
	},
	{
		.name = "emptyCRheader",
		.msg = "\rdata\r\n",
		.filters = 0
	},
	{
		.name = "dots",
		.msg = "Subject: dot-test\r\n.\r\n..\r\n.",
		.filters = 1
	},
	{
		.name = "8bitLF",
		.msg = "Subject: 8bit recode test\r\n"
		       "Content-Type: multipart/mixed;\r\n"
		       " boundary=\"------------0008\"\r\n"
		       "\r\n"
		       "This is a multi-part message in MIME format.\r\n"
		       "--------------0008\r\n"
		       "Content-Type: text/plain; charset=ISO-8859-15; format=flowed\r\n"
		       "Content-Transfer-Encoding: 8bit\r\n"
		       "\n"
		       "Hi,\n"
		       "\n"
		       "This is a test mail with an Euro sign: \244\n"
		       "\r\n"
		       "--------------0008\r\n"
		       "Content-Type: text/plain; charset=ISO-8859-15; format=flowed\r\n"
		       "Content-Transfer-Encoding: 8bit\r\n"
		       "\r"
		       "Hi,\n"
		       "\n"
		       "This is a test mail with an Euro sign: \244\n"
		       "\r\n"
		       "--------------0008--\r\n"
		       "\r\n",
		.filters = 0
	},
	{
		.name = "8bit+base64",
		.msg = "Subject: multipart recode test message\r\n"
		       "Content-Type: multipart/mixed;\r\n"
		       " boundary=\"------------0008\"\r\n"
		       "\r\n"
		       "This is a multi-part message in MIME format.\r\n"
		       "--------------0008\r\n"
		       "Content-Type: text/plain; charset=ISO-8859-15; format=flowed\r\n"
		       "Content-Transfer-Encoding: 8bit\r\n"
		       "\r\n"
		       "Hi,\r\n"
		       "\r\n"
		       "This is a test mail with an Euro sign: \244\r\n"
		       "\r\n"
		       "--------------0008\r\n"
		       "Content-Type: application/pdf;\r\n"
		       " name=\"dummy.pdf\"\r\n"
		       "Content-Transfer-Encoding: base64\r\n"
		       "Content-Disposition: attachment;\r\n"
		       " filename*0=\"dummy.pdf\"\r\n"
		       "\r\n"
		       "JVBE\r\n"
		       "\r\n"
		       "--------------0008--\r\n"
		       "\r\n",
		.filters = 2
	},
	{
		.name = NULL
	}
};
static unsigned int usepattern;

static void
dots_detector(const char *msg, const size_t len)
{
	static const char dotstr[] = "\r\n..\r\n...\r\n..\r\n.\r\n";
	/* message must end with CRLF..CRLF...CRLF..CRLF.CRLF */
	const char *tmp = strstr(msg, dotstr);
	if (tmp != msg + len - strlen(dotstr)) {
		fputs("invalid dot recoding\n", stderr);
		exit(EINVAL);
	}

}

static void
recode_detector(const char *msg, const size_t len)
{
	static const char ct_str[] = "Content-Type:";
	unsigned int ct_cnt = 0;
	unsigned int ct_cnt_orig = 0;
	const char *tmp_msg = msg;
	const char *tmp_orig = testpatterns[usepattern].msg;

	if (need_recode(msg, len) != 0) {
		fputs("The message should not need recoding after recoding\n", stderr);
		exit(EINVAL);
	}

	do {
		tmp_msg = strstr(tmp_msg + 1, ct_str);
		if (tmp_msg != NULL)
			ct_cnt++;
	} while (tmp_msg != NULL);

	do {
		tmp_orig = strstr(tmp_orig + 1, ct_str);
		if (tmp_orig != NULL)
			ct_cnt_orig++;
	} while (tmp_orig != NULL);

	assert(ct_cnt_orig == 3);

	if (ct_cnt_orig != ct_cnt) {
		fputs("There are not as much Content-Type: lines in both messages\n", stderr);
		exit(EINVAL);
	}

	tmp_msg = strstr(msg, ct_str);
	tmp_msg = strstr(tmp_msg + 1, ct_str);
	tmp_orig = strstr(testpatterns[usepattern].msg, ct_str);
	tmp_orig = strstr(tmp_orig + 1, ct_str);

	if (tmp_msg - msg != tmp_orig - testpatterns[usepattern].msg) {
		fputs("The length to the second Content-Type header differs in original and recoded message\n", stderr);
		exit(EINVAL);
	}

	if (memcmp(msg, testpatterns[usepattern].msg, tmp_msg - msg) != 0) {
		fputs("The messages until the second Content-Type header differ\n", stderr);
		exit(EINVAL);
	}

	tmp_msg = strstr(tmp_msg + 1, ct_str);
	tmp_orig = strstr(tmp_orig + 1, ct_str);

	/* compare only the length of tmp_orig here as .CRLF is appended */
	if (strncmp(tmp_msg, tmp_orig, strlen(tmp_orig)) != 0) {
		fputs("The messages differ after the third Content-Type header\n", stderr);
fputs(msg, stderr);
		exit(EINVAL);
	}
}

/**
 * @brief check if message has only valid CRLF sequences
 * @param msg area to check
 * @param len length of msg
 *
 * This also checks that there is exactly one CRLF.CRLF sequence
 * within msg and that is at the end of the buffer.
 */

static void
checkcrlf(const char *msg, const size_t len)
{
	const char *tmp;
	size_t pos;
	size_t linestart = 0;

	/* first check: message must end with CRLF.CRLF and that
	 * may never occur within the message. */
	tmp = strstr(msg, "\r\n.\r\n");
	if (tmp != msg + len - 5) {
		fputs("CRLF.CRLF sequence found at bad position\n", stderr);
		exit(EINVAL);
	}

	for (pos = 0; pos < len; pos++) {
		switch (msg[pos]) {
		case '\r':
			/* we know the message will not end with a stray CR */
			if (msg[++pos] != '\n') {
				fputs("detected stray CR in message\n", stderr);
				exit(EINVAL);
			}
			if (pos - linestart > 1002) {
				fputs("detected unrecoded long line\n", stderr);
				exit(EINVAL);
			}
			linestart = pos;
			break;
		case '\n':
			/* CRLF sequences would have been caught by '\r' case */
			fputs("detected stray LF in message\n", stderr);
			exit(EINVAL);
		default:
			break;
		}
	}
}

int
netwrite(const char *msg)
{
	switch (state) {
	case ST_START:
		if (strcasecmp(msg, "DATA\r\n") != 0) {
			fputs("invalid message received: ", stderr);
			fputs(msg, stderr);
			fputc('\n', stderr);
			exit(EINVAL);
		}
		state = ST_DATA;
		break;
	case ST_354:
		return netnwrite(msg, strlen(msg));
	default:
		fputs("netwrite() called unexpected, argument: ", stderr);
		fputs(msg, stderr);
		fputc('\n', stderr);
		exit(EFAULT);
	}

	return 0;
}

int
netget(void)
{
	switch (state) {
	case ST_DATA:
		state = ST_354;
		return 354;
	case ST_DATAEND:
		state = ST_DATADONE;
		return 250;
	default:
		fputs("netget() called unexpected\n", stderr);
		exit(EFAULT);
	}
}

int
checkreply(const char *status, const char **pre, const int mask)
{
	if (strcmp("KZD", status) != 0)
		exit(EINVAL);

	if (mask != 1)
		exit(EINVAL);

	checkcrlf(outbuf, outpos);

	switch (testpatterns[usepattern].filters) {
	case 0:
		break;
	case 1:
		dots_detector(outbuf, outpos);
		break;
	case 2:
		recode_detector(outbuf, outpos);
		break;
	default:
		exit(EFAULT);
	}

	exit(0);
}

int
netnwrite(const char *s, const size_t l)
{
	if (state != ST_354) {
		fputs("netnwrite() called unexpected\n", stderr);
		exit(EFAULT);
	}

	if (outpos + l >= outlen) {
		fputs("output overflow\n", stderr);
		exit(EINVAL);
	}

	memcpy(outbuf + outpos, s, l);
	outpos += l;

	return 0;
}

void
quit(void)
{
	fputs("quit() called unexpected\n", stderr);
	exit(EFAULT);
}

void
log_write(int priority, const char *s)
{
	fputs("log_write() called unexpected, message: ", stderr);
	fputs(s, stderr);
	fputc('\n', stderr);
	exit(EFAULT);

}

int main(int argc, char **argv)
{
	if (argc == 1) {
		fputs("Usage: ", stderr);
		fputs(argv[0], stderr);
		fputs(" testpattern\n", stderr);
		return EFAULT;
	}

	heloname.s = "foo.bar.example.com";
	heloname.len = strlen(heloname.s);

	for (usepattern = 0; testpatterns[usepattern].name != NULL; usepattern++) {
		if (strcmp(testpatterns[usepattern].name, argv[1]) == 0)
			break;
	}

	if (testpatterns[usepattern].name == NULL) {
		fputs("invalid testpattern specified\n", stderr);
		return EFAULT;
	}

	/* worst case we need to QP-encode every byte and append CRLF.CRLF */
	outlen = strlen(testpatterns[usepattern].msg) * 3 + 5;
	outbuf = malloc(outlen);
	if (outbuf == NULL)
		return ENOMEM;

	msgdata = testpatterns[usepattern].msg;
	msgsize = strlen(msgdata);

	ascii = need_recode(msgdata, msgsize);
	outpos = 0;
	send_data();

	fputs("end of program reached when it should not\n", stderr);
	return EFAULT;
}
