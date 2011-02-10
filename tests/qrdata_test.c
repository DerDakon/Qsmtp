#define _ISOC99_SOURCE
#include "netio.h"
#include "qrdata.h"
#include "qremote.h"
#include "test_io/testcase_io.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum datastate {
	ST_START,
	ST_DATA,
	ST_354,
	ST_DATAEND,
	ST_DATADONE,
	ST_FINISH
};

static enum datastate state = ST_START;

unsigned int may_log_count;

string heloname;
unsigned int smtpext;

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
	unsigned int recodeflag;
	unsigned int log_count;
} testpatterns[] = {
	{
		.name = "simple",
		.msg = "Subject: simple test\r\n\r\n\r\n",
		.filters = 3,
		.recodeflag = 0,
		.log_count = 0
	},
	{
		.name = "crlfmixup",
		.msg = "Subject: CRLF test\r\r\n\n\r\n\n\r\r ",
		.filters = 3,
		.recodeflag = 0,
		.log_count = 0
	},
	{
		.name = "longBodyLine",
		.msg = "Subject: long body line\r\n\r\n"
				"   50 78901234567890123456789012345678901234567890"
				"  100 78901234567890123 56789012345678901234567890"
				"  150 12345678901234567890123456789012345678901\t34"
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
				" 1050 12345678901234567890123456789012345678901234 \r\n"
				"another line\t\r\n",
		.filters = 0,
		.recodeflag = 2,
		.log_count = 0
	},
	{
		.name = "longHeaderLineCR",
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
				" 1050 12345678901234567890123456789012345678901234\r"
				"From: <foo@bar.example.com>\r",
		.filters = 3,
		.recodeflag = 4,
		.log_count = 0
	},
	{
		.name = "longHeaderLineLF",
		.msg = "From: <foo@bar.example.com>\nSubject: long header line"
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
				"__750_12345678901234567890123456789012345678901234"
				"__800_12345678901234567890123456789012345678901234"
				"__850_12345678901234567890123456789012345678901234"
				"__900_12345678901234567890123456789012345678901234"
				"__950_12345678901234567890123456789012345678901234"
				" 1000 12345678901234567890123456789012345678901234\n",
		.filters = 3,
		.recodeflag = 4,
		.log_count = 0
	},
	{
		.name = "longHeaderLine",
		.msg = "From: <foo@bar.example.com>\nSubject: long header line"
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
				" 1050 12345678901234567890123456789012345678901234",
		.filters = 3,
		.recodeflag = 4,
		.log_count = 0
	},
	{
		.name = "emptyLFheader",
		.msg = "\ndata\r\n",
		.filters = 0,
		.recodeflag = 0,
		.log_count = 0
	},
	{
		.name = "emptyCRheader",
		.msg = "\rdata\r\n",
		.filters = 0,
		.recodeflag = 0,
		.log_count = 0
	},
	{
		.name = "noLFatEnd",
		.msg = "Subject: missing linefeed\r\n\r\nfoo bar test",
		.filters = 3,
		.recodeflag = 0,
		.log_count = 0
	},
	{
		.name = "dots",
		.msg = "Subject: dot-test\r\n.\r\n..\r\n.",
		.filters = 1,
		.recodeflag = 0,
		.log_count = 0
	},
	{
		.name = "8bitHeader",
		.msg = "Subject: garbage \244\r\n\r\n",
		.filters = 0,
		.recodeflag = 1,
		.log_count = 0
	},
	{
		.name = "emptyLFheaderWith8bit",
		.msg = "\ndata \244 \r\n",
		.filters = 0,
		.recodeflag = 1,
		.log_count = 1
	},
	{
		.name = "emptyCRheaderWith8bit",
		.msg = "\rdata \244 \r\n",
		.filters = 0,
		.recodeflag = 1,
		.log_count = 1
	},
	{
		.name = "emptyCRLFheaderWith8bit",
		.msg = "\r\ndata \244 \r\n",
		.filters = 0,
		.recodeflag = 1,
		.log_count = 1
	},
	{
		.name = "8bitLF",
		.msg = "Subject: 8bit recode test\r"
		       "Content-Type: multipart/mixed;\r"
		       " boundary=\"------------0008\"\r"
		       "\r"
		       "This is a multi-part message in MIME format.\n"
		       "--------------0008\n"
		       "Content-Type: text/plain; charset=ISO-8859-15; format=flowed\n"
		       "Content-Transfer-Encoding: 8bit\n"
		       "\n"
		       "Hi,\n"
		       "\n"
		       "This is a test mail with an Euro sign: \244\n"
		       "\n"
		       "--------------0008\r"
		       "Content-Type: text/plain; charset=ISO-8859-15; format=flowed\r"
		       "Content-Transfer-Encoding: 8bit\r"
		       "\r"
		       "Hi,\r"
		       "\r"
		       "This is a test mail with an Euro sign: \244\r"
		       "\r"
		       "--------------0008--\r"
		       "\r",
		.filters = 0,
		.recodeflag = 1,
		.log_count = 0
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
		.filters = 2,
		.recodeflag = 1,
		.log_count = 0
	},
	{
		.name = "InvalidPreamble",
		.msg = "Subject: Preamble must not contain 8bit data\r"
		       "Content-Type: multipart/mixed;\r"
		       " boundary=\"------------0008\"\r"
		       "\r"
		       "This is a multi-part message in MIME format.\n"
		       "This preamble is invalid because of this 8bit char: \244\n"
		       "--------------0008--\r"
		       "We now have immediately a final boundary so we don't really\n"
		       "have any MIME-parts at all. And this trailer is also invalid\r"
		       "because of 8bit data: \244\n"
		       "\r",
		.filters = 0,
		.recodeflag = 1,
		.log_count = 2
	},
	{
		.name = "NoEndBoundary",
		.msg = "Subject: end boundary is missing\r"
		       "Content-Type: multipart/mixed;\r"
		       " boundary=\"------------0008\"\r"
		       "\r"
		       "--------------0008\r"
		       "Content-Type: text/plain; charset=iso-8859-15\n"
		       "\n"
		       "This is the data part and it is again about money: \244\n"
		       "\r",
		.filters = 0,
		.recodeflag = 1,
		.log_count = 2
	},
	{
		.name = "EndInNotFinalBoundary",
		.msg = "Subject: end boundary is missing\r"
		       "Content-Type: multipart/mixed;\r"
		       " boundary=\"------------0008\"\r"
		       "\r"
		       "--------------0008\r"
		       "Content-Type: text/plain; charset=iso-8859-15\n"
		       "\n"
		       "This is the data part and it is again about money: \244\n"
		       "This line is long enough so it needs to be wrapped exaclty at the first do.t.\n"
		       "--------------0008",
		.filters = 0,
		.recodeflag = 1,
		.log_count = 2
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
		exit(EINVAL);
	}
}

/**
 * \brief check if the wrapped header is still the same
 * \param msg recoded message
 * \param len length of recoded message
 * 
 * This compares the original and the recoded messages. It
 * takes into account that the amount of whitespace may not
 * be preserved after recoding.
 */
static void
hdrwrap_detector(const char *msg, const size_t len)
{
	const char *tmp_orig = testpatterns[usepattern].msg;
	const size_t orig_len = strlen(tmp_orig);
	size_t orig_off = 0;
	size_t new_off = 0;

	do {
		if (isblank(msg[new_off]) && isblank(tmp_orig[orig_off])) {
			do {
				new_off++;
			} while (isblank(msg[new_off]));
			do {
				orig_off++;
			} while (isblank(tmp_orig[orig_off]));
		}

		if ((msg[new_off] == '\r') && ((tmp_orig[orig_off] == '\r') || (tmp_orig[orig_off] == '\n'))) {
			new_off++;
			assert(msg[new_off] == '\n');
			new_off++;

			if (tmp_orig[orig_off] == '\r')
				orig_off++;
			if (tmp_orig[orig_off] == '\n')
				orig_off++;
		} else if (msg[new_off] == '\r') {
			new_off++;
			assert(msg[new_off] == '\n');
			new_off++;

			while (isblank(msg[new_off])) {
				new_off++;
			}
		}

		if (orig_off == orig_len)
			break;

		/* end of header reached */
		if ((msg[new_off] == '\r') && ((tmp_orig[orig_off] == '\r') || (tmp_orig[orig_off] == '\n'))) {
			new_off++;
			assert(msg[new_off] == '\n');
			return;
		}

		if (msg[new_off] != tmp_orig[orig_off]) {
			fprintf(stderr, "characters 0x%x (%c, offs %lu) and 0x%x (%c, offs %lu) do not match\n",
					msg[new_off], msg[new_off], (unsigned long)new_off,
					tmp_orig[orig_off], tmp_orig[orig_off], (unsigned long)orig_off);
			fprintf(stderr, "orig message: %s\n", tmp_orig);
			fprintf(stderr, "recoded message: %s\n", msg);
			exit(EINVAL);
		}
		new_off++;
		orig_off++;
	} while ((new_off < len) && (orig_off < orig_len));

	if ((orig_off == orig_len) && (new_off < len)) {
		while ((msg[new_off] == '\r') || (msg[new_off] == '\n'))
			new_off++;

		assert(strncmp(msg + new_off, ".\r\n", 3) == 0);
		assert(new_off == len - 3);
	}
	assert(orig_off == orig_len);
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
checkreply(const char *status, const char **pre __attribute__ ((unused)), const int mask)
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
	case 3:
		hdrwrap_detector(outbuf, outpos);
		break;
	default:
		exit(EFAULT);
	}

	free(outbuf);
	outbuf = NULL;
	exit(0);
}

int
test_netnwrite(const char *s, const size_t l)
{
	const char *errmsg = NULL;

	switch (state) {
	case ST_START:
		if ((strncasecmp(s, "DATA\r\n", l) != 0) || (l != strlen("DATA\r\n"))) {
			errmsg = "invalid message received: ";
			fflush(stderr);
			write(2, errmsg, strlen(errmsg));
			write(2, s, l);
			write(2, "\n", l);
			exit(EINVAL);
		}
		state = ST_DATA;
		return 0;
	case ST_354:
		if (outpos + l >= outlen) {
			fputs("output overflow\n", stderr);
			exit(EINVAL);
		}

		memcpy(outbuf + outpos, s, l);
		outpos += l;
		return 0;
	default:
		errmsg = "netnwrite() called unexpected, argument: ";
		fflush(stderr);
		write(2, errmsg, strlen(errmsg));
		write(2, s, l);
		write(2, "\n", 1);
		exit(EFAULT);
	}
}

void
quit(void)
{
	fputs("quit() called unexpected\n", stderr);
	exit(EFAULT);
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

int main(int argc, char **argv)
{
	unsigned int ascii;

	testcase_setup_log_write(test_log_write);
	testcase_setup_netnwrite(test_netnwrite);

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

	may_log_count = testpatterns[usepattern].log_count;

	/* worst case we need to QP-encode every byte and append CRLF.CRLF */
	/* also there could be some additional headers or boundaries */
	outlen = strlen(testpatterns[usepattern].msg) * 3 + 200;
	outbuf = malloc(outlen);
	if (outbuf == NULL)
		return ENOMEM;

	msgdata = testpatterns[usepattern].msg;
	msgsize = strlen(msgdata);

	ascii = need_recode(msgdata, msgsize);

	if (ascii != testpatterns[usepattern].recodeflag) {
		fprintf(stderr, "need_recode() returned 0x%x, expected was 0x%x\n", ascii, testpatterns[usepattern].recodeflag);
		return EFAULT;
	}

	outpos = 0;
	send_data(ascii);

	fputs("end of program reached when it should not\n", stderr);
	return EFAULT;
}
