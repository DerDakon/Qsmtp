#include <qremote/client.h>
#include <qremote/greeting.h>
#include <qremote/qrdata.h>
#include <qremote/qremote.h>

#include "test_io/testcase_io.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *rhost = (char *)"testremote.example.net";
unsigned int smtpext;
off_t msgsize = 12345;

static char netbuffer[1024];
static const char *netbuffer_next[5];
static const char *checkreplies;	// return values for checkreplies

int
checkreply(const char *status, const char **pre, const int mask)
{
	const char *mailerrmsg[] = { "Connected to ", rhost, " but sender was rejected\n", NULL };
	const char *sexp;	// expected status
	int emask;	// expected mask
	int ret;

	if ((strlen(checkreplies) < 2) || (*checkreplies == ':') || (checkreplies[1] == ':'))
		exit(EINVAL);

	switch (*checkreplies) {
	case '0':
		sexp = NULL;
		emask = 0;
		break;
	case 's':
		sexp = "rsh";
		emask = 8;
		break;
	case 'Z':
		sexp = " ZD";
		emask = 6;
		break;
	default:
		exit(EINVAL);
	}

	if (mask != emask) {
		fprintf(stderr, "unexpected mask argument 0x%x to %s, expected 0x%x\n", mask, __func__, emask);
		exit(EFAULT);
	}

	if ((status == NULL) || (strcmp(status, "rsh") == 0)) {
		if (pre != NULL) {
			fprintf(stderr, "unexpected arguments to %s\n", __func__);
			exit(EFAULT);
		}
	} else if (strcmp(status, " ZD") == 0) {
		int err = 0;
		unsigned int i;

		for (i = 0; (i < 3) && !err; i++)
			err = strcmp(pre[i], mailerrmsg[i]);

		if (!err)
			err = (pre[3] != NULL);

		if (err) {
			fprintf(stderr, "unexpected arguments to %s\n", __func__);
			exit(EFAULT);
		}
	} else {
		fprintf(stderr, "unexpected arguments to %s\n", __func__);
		exit(EFAULT);
	}

	if (sexp == NULL) {
		if (status != NULL) {
			fprintf(stderr, "%s('%s', ...) was called, but NULL was expected as argument\n", __func__, status);
			exit(EFAULT);
		}
	} else {
		if ((status == NULL) || (strcmp(sexp, status) != 0)) {
			fprintf(stderr, "%s('%s', ...) was called, but '%s' was expected as argument\n", __func__, status, sexp);
			exit(EFAULT);
		}
	}

	switch (checkreplies[1]) {
	case '2':
		ret = 250;
		break;
	case '4':
		ret = 421;
		break;
	case '5':
		ret = 510;
		break;
	default:
		exit(EINVAL);
	}

	checkreplies += 2;

	if (!(smtpext & esmtp_pipelining)) {
		netnwrite_msg = netbuffer_next[0];
		memmove(netbuffer_next, netbuffer_next + 1, sizeof(netbuffer_next) - sizeof(netbuffer_next[0]));
	}

	return ret;
}

// The arguments are expected as follows:
// 1: control string, consisting of REXX:checkreplies
//    R: recodeflag to set ('0'..'3')
//    E: expected return code of send_envelope (either '0' or '1')
//    XX: smtpext value to set (2 hex characters)
//    checkreplies: contol string for checkreply ([0sZ][245])+
// 2: mail from
// 3+: recipients
// LAST: expected network messages,
// NOTE: this is the same layout as Qremote, just the first argument is
//       different and the last one is new
// LF in the last argument is expanded to CRLF, | is used to delimit the
// different network messagess

int
main(int argc, char *argv[])
{
	int recodeflag;
	int r;
	char *end;

	if (argc < 4)
		return EINVAL;

	switch (*(argv[1])) {
	case '0':
	case '1':
	case '2':
	case '3':
		recodeflag = *(argv[1]) - '0';
		break;
	default:
		return EINVAL;
	}

	checkreplies = strchr(argv[1], ':');
	if (checkreplies == NULL)
		return EINVAL;
	if (*++checkreplies != 'Z')
		return EINVAL;

	if (!isxdigit(argv[1][2]) || !isxdigit(argv[1][3]))
		return EINVAL;

	char hx[3] = { argv[1][2], argv[1][3], '\0' };
	smtpext = strtol(hx, NULL, 16);

	testcase_setup_net_write_multiline(testcase_native_net_write_multiline);
	testcase_setup_netnwrite(testcase_netnwrite_compare);
	testcase_setup_net_writen(testcase_net_writen_combine);

	netnwrite_msg = netbuffer;

	strncpy(netbuffer, argv[argc - 1], sizeof(netbuffer));

	// looks like one cannot pass \r as argument when using CMake
	end = netbuffer;
	while ((end = strchr(end, '\n')) != NULL) {
		memmove(end + 1, end, strlen(end));
		*end = '\r';
		end += 2;
	}

	unsigned int i = 0;
	while ((end = strrchr(netbuffer, '|')) != NULL) {
		*end = '\0';
		netbuffer_next[i++] = end + 1;
		if (i >= sizeof(netbuffer_next) / sizeof(netbuffer_next[i]) - 1)
			return EFAULT;
	}
	if (i > 1) {
		// the entries in netbuffer_next are in reverse order, fix this
		unsigned int j = 0;
		i--;

		while (i > j) {
			const char *s = netbuffer_next[j];
			netbuffer_next[j++] = netbuffer_next[i];
			netbuffer_next[i--] = s;
		}
	}

	if ((smtpext & esmtp_pipelining) && (*netbuffer_next != NULL))
		netnwrite_msg_next = netbuffer_next;

	r = send_envelope(recodeflag, argv[2], argc - 4, argv + 3);

	if (!(smtpext & esmtp_pipelining) && *netbuffer_next) {
		fprintf(stderr, "too few network messages were sent\n");
		return EFAULT;
	}

	testcase_netnwrite_check("Qremote envelope");

	return r != argv[1][1] - '0';
}
