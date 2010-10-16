#include "netio.h"
#include "qrdata.h"
#include "qremote.h"

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
		.name = "dots",
		.msg = "Subject: dot-test\r\n.\r\n..\r\n.",
		.filters = 1
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

	outpos = 0;
	send_data();

	fputs("end of program reached when it should not\n", stderr);
	return EFAULT;
}
