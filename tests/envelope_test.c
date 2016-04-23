#include <qremote/client.h>
#include <qremote/greeting.h>
#include <qremote/qrdata.h>
#include <qremote/qremote.h>

#include "test_io/testcase_io.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *rhost = (char *)"testremote.example.net";
unsigned int smtpext;
off_t msgsize = 12345;
char netbuffer[1024];
int hasmorenetbuf;

static const char *checkreplies;	// return values for checkreplies

int
checkreply(const char *status, const char **pre, const int mask)
{
	const char *mailerrmsg[] = { "Connected to ", rhost, " but sender was rejected", NULL };
	const char *sexp;	// expected status
	int ret;

	if ((strlen(checkreplies) < 2) || (*checkreplies == ':') || (checkreplies[1] == ':'))
		exit(EINVAL);

	switch (*checkreplies) {
	case '0':
		sexp = NULL;
		break;
	case 's':
		sexp = " sh";
		break;
	case 'Z':
		sexp = " ZD";
		break;
	default:
		exit(EINVAL);
	}

	if ((status == NULL) || (strcmp(status, " sh") == 0)) {
		if ((pre != NULL) || (mask != 0)) {
			fprintf(stderr, "unexpected arguments to %s\n", __func__);
			exit(EFAULT);
		}
	} else if (strcmp(status, " ZD") == 0) {
		int err = (mask != 6);
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

	switch (*++checkreplies) {
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

	checkreplies++;

	if (hasmorenetbuf) {
		size_t skip = strlen(netbuffer) + 1;
		hasmorenetbuf--;
		memmove(netbuffer, netbuffer + skip, sizeof(netbuffer) - skip);
		netnwrite_msg = netbuffer;
	}

	return ret;
}

static unsigned int scount;

void
write_status_raw(const char *str, const size_t len)
{
	if ((str == NULL) || (strcmp(str, "r") != 0) || (len != 2)) {
		fprintf(stderr, "%s('%s', %zu) called, but ('r', 2) expected\n", __func__, str, len);
		exit(EFAULT);
	}

	if (scount-- == 0) {
		fprintf(stderr, "%s() called too often\n", __func__);
		exit(EFAULT);
	}
}

// The arguments are expected as follows:
// 1: control string, consisting of REXX:checkreplies:rawstatus
//    R: recodeflag to set ('0'..'3')
//    E: expected return code of send_envelope (either '0' or '1')
//    XX: smtpext value to set (2 hex characters)
//    checkreplies: contol string for checkreply ([0sZ][245])+
//    rawstatus: number of calls to write_status_raw() that must happen
// 2: mail from
// 3+: recipients
// NOTE: this is the same layout as Qremote, just the first argument is
//       different

int
main(int argc, char *argv[])
{
	int recodeflag;
	const char *rawstatus;
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

	rawstatus = strchr(checkreplies, ':');
	if (rawstatus == NULL)
		return EINVAL;

	scount = strtoul(++rawstatus, &end, 10);
	if (*end != '\0')
		return EINVAL;

	if (!isxdigit(argv[1][2]) || !isxdigit(argv[1][3]))
		return EINVAL;

	char hx[3] = { argv[1][2], argv[1][3], '\0' };
	smtpext = strtol(hx, NULL, 16);

	testcase_setup_net_write_multiline(testcase_native_net_write_multiline);
	testcase_setup_netnwrite(testcase_netnwrite_compare);
	testcase_setup_net_writen(testcase_net_writen_combine);

	netnwrite_msg = netbuffer;

	snprintf(netbuffer, sizeof(netbuffer), "MAIL FROM:<%s>", argv[2]);
	if (smtpext & esmtp_size)
		strcat(netbuffer, " SIZE=12345");
	if (smtpext & esmtp_8bitmime) {
		if (recodeflag & 1)
			strcat(netbuffer, " BODY=8BITMIME");
		else
			strcat(netbuffer, " BODY=7BIT");
	}

	if (smtpext & esmtp_pipelining) {
		strcat(netbuffer, "\r\nRCPT TO:<");
		strcat(netbuffer, argv[3]);
		strcat(netbuffer, ">\r\n");
	} else {
		strcat(netbuffer, "\r\n|RCPT TO:<");
		strcat(netbuffer, argv[3]);
		strcat(netbuffer, ">\r\n");
	}

	while ((end = strrchr(netbuffer, '|')) != NULL) {
		hasmorenetbuf++;
		*end = '\0';
	}

	r = send_envelope(recodeflag, argv[2], argc - 3, argv + 3);

	if (scount != 0) {
		fprintf(stderr, "too few calls to write_status_raw(), %u calls missing\n", scount);
		return EFAULT;
	}

	return r != argv[1][1] - '0';
}
