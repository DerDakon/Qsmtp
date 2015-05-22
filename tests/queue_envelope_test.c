#include <qsmtpd/queue.h>
#include <qsmtpd/qsmtpd.h>
#include <tls.h>
#include "test_io/testcase_io.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct xmitstat xmitstat;
unsigned int goodrcpt;
string liphost;
static struct smtpcomm command;
struct smtpcomm *current_command = &command;
static char logbuffer[2048];

pid_t
fork_clean()
{
	exit(EFAULT);
}

int
pipe_move(int p[2] __attribute__((unused)), int target __attribute__((unused)))
{
	exit(EFAULT);
}

void
freedata(void)
{
}

void
tc_log_writen(int prio __attribute__((unused)), const char **msg)
{
	unsigned int i = 0;

	while (msg[i] != NULL) {
		strncat(logbuffer, msg[i], sizeof(logbuffer) - strlen(logbuffer) - 1);
		i++;
	}
	strncat(logbuffer, "\n", sizeof(logbuffer) - strlen(logbuffer) - 1);
}

static int
check_logmsg(const char *msg)
{
	int r = 0;

	if (strcmp(msg, logbuffer) != 0) {
		fprintf(stderr, "log messages do not match, expected:\n%s\ngot:\n%s\n",
				msg, logbuffer);
		r = 1;
	}

	memset(logbuffer, 0, sizeof(logbuffer));

	return r;
}

static int
test_invalid_close(void)
{
	int r;

	queuefd_data = -1;

	errno = 0;
	r = queue_envelope(0, 0);

	if ((r != -1) || (errno != EBADF)) {
		fprintf(stderr, "calling queue_envelope() with invalid returned %i/%i\n",
			r, errno);
		return 1;
	}

	return check_logmsg("");
}

static int
test_invalid_write(void)
{
	int ret = 0;
	int r;

	queuefd_data = open(".", O_RDONLY | O_CLOEXEC);
	queuefd_hdr = open(".", O_RDONLY | O_CLOEXEC);

	goodrcpt = 1;

	errno = 0;
	r = queue_envelope(0, 0);

	if ((r != -1) || (errno != EBADF)) {
		fprintf(stderr, "calling queue_envelope() with invalid returned %i/%i\n",
			r, errno);
		ret++;
	}

	if (queuefd_data != -1) {
		fprintf(stderr, "queue_envelope() did not reset queuefd_data\n");
		ret++;
	}

	if (queuefd_hdr != -1) {
		fprintf(stderr, "queue_envelope() did not reset queuefd_hdr\n");
		ret++;
	}

	ret += check_logmsg("");

	return ret;
}

static int
test_invalid_write2(void)
{
	int ret = 0;
	int r;

	queuefd_data = open(".", O_RDONLY | O_CLOEXEC);
	queuefd_hdr = -1;

	goodrcpt = 1;

	errno = 0;
	r = queue_envelope(0, 0);

	if ((r != -1) || (errno != EBADF)) {
		fprintf(stderr, "calling queue_envelope() with invalid returned %i/%i\n",
			r, errno);
		ret++;
	}

	if (queuefd_data != -1) {
		fprintf(stderr, "queue_envelope() did not reset queuefd_data\n");
		ret++;
	}

	if (queuefd_hdr != -1) {
		fprintf(stderr, "queue_envelope() did not reset queuefd_hdr\n");
		ret++;
	}

	ret += check_logmsg("");

	return ret;
}

static void
create_rcpt(const char *addr)
{
	struct recip *r;

	if (addr == NULL)
		return;

	r = malloc(sizeof(*r));
	if (r == NULL)
		exit(ENOMEM);

	r->ok = (addr[0] != '!');	/* user will be rejected until we change this explicitely */
	if (r->ok) {
		dupstr(&(r->to), addr);
		goodrcpt++;
	} else {
		dupstr(&(r->to), addr + 1);
	}
	TAILQ_INSERT_TAIL(&head, r, entries);
}

static int
test_log_messages(void)
{
	int ret = 0;
	const char envelope1[] = "F\0Tfoo@example.com\0";
	const char envelope1ip[] = "Fbaz@example.org\0Tfoo@ip.example.com\0";
	const char envelope2[] = "F\0Tfoo@example.com\0Tbar@example.com\0";
	const char envelope1a[] = "Fbaz@example.org\0Tfoo@example.com\0";
	const char envelope2a[] = "Fbaz@example.org\0Tfoo@example.com\0Tbar@example.com\0";
	struct {
		const char *rcpt1, *rcpt2;	/* if string begins with ! the recipient will be marked as invalid */
		const unsigned int chunked:1;
		const unsigned int encrypted:1;
		const unsigned int spacebug:1;
		const unsigned long msgsize;
		const char *from;
		const char *authname;
		const char *logmsg;	/* expected log message */
		const char *envelope;	/* expected envelope data */
		const ssize_t envsize;	/* length of envelope, since that contains 0-bytes */
	} testpattern[] = {
		{
			.rcpt1 = "foo@example.com",
			.logmsg = "received message to <foo@example.com> from <> from IP [::ffff:172.28.19.44] (0 bytes)\n",
			.envelope = envelope1,
			.envsize = sizeof(envelope1)
		},
		{
			.rcpt1 = "foo@example.com",
			.rcpt2 = "!bar@example.com",
			.msgsize = 17,
			.logmsg = "received message to <foo@example.com> from <> from IP [::ffff:172.28.19.44] (17 bytes)\n",
			.envelope = envelope1,
			.envsize = sizeof(envelope1)
		},
		{
			.rcpt1 = "foo@example.com",
			.rcpt2 = "bar@example.com",
			.msgsize = 19,
			.from = "baz@example.org",
			.logmsg = "received message to <foo@example.com> from <baz@example.org> from IP [::ffff:172.28.19.44] (19 bytes, 2 recipients)\n"
				"received message to <bar@example.com> from <baz@example.org> from IP [::ffff:172.28.19.44] (19 bytes, 2 recipients)\n",
			.envelope = envelope2a,
			.envsize = sizeof(envelope2a)
		},
		{
			.rcpt1 = "foo@example.com",
			.rcpt2 = "!bar@example.com",
			.encrypted = 1,
			.msgsize = 23,
			.logmsg = "received (NONE) encrypted message to <foo@example.com> from <> from IP [::ffff:172.28.19.44] (23 bytes)\n",
			.envelope = envelope1,
			.envsize = sizeof(envelope1)
		},
		{
			.rcpt1 = "foo@example.com",
			.rcpt2 = "bar@example.com",
			.chunked = 1,
			.msgsize = 29,
			.logmsg = "received chunked message to <foo@example.com> from <> from IP [::ffff:172.28.19.44] (29 bytes, 2 recipients)\n"
				"received chunked message to <bar@example.com> from <> from IP [::ffff:172.28.19.44] (29 bytes, 2 recipients)\n",
			.envelope = envelope2,
			.envsize = sizeof(envelope2)
		},
		{
			.rcpt1 = "foo@example.com",
			.rcpt2 = "!bar@example.com",
			.spacebug = 1,
			.msgsize = 31,
			.from = "baz@example.org",
			.logmsg = "received message with SMTP space bug to <foo@example.com> from <baz@example.org> from IP [::ffff:172.28.19.44] (31 bytes)\n",
			.envelope = envelope1a,
			.envsize = sizeof(envelope1a)
		},
		{
			.rcpt1 = "foo@example.com",
			.rcpt2 = "!bar@example.com",
			.encrypted = 1,
			.chunked = 1,
			.msgsize = 37,
			.from = "baz@example.org",
			.authname = "baz@example.org",
			.logmsg = "received (NONE) encrypted chunked message to <foo@example.com> from <baz@example.org> (authenticated) from IP [::ffff:172.28.19.44] (37 bytes)\n",
			.envelope = envelope1a,
			.envsize = sizeof(envelope1a)
		},
		{
			.rcpt1 = "foo@example.com",
			.rcpt2 = "bar@example.com",
			.encrypted = 1,
			.spacebug = 1,
			.msgsize = 41,
			.logmsg = "received (NONE) encrypted message with SMTP space bug to <foo@example.com> from <> from IP [::ffff:172.28.19.44] (41 bytes, 2 recipients)\n"
				"received (NONE) encrypted message with SMTP space bug to <bar@example.com> from <> from IP [::ffff:172.28.19.44] (41 bytes, 2 recipients)\n",
			.envelope = envelope2,
			.envsize = sizeof(envelope2)
		},
		{
			.rcpt1 = "foo@example.com",
			.rcpt2 = "bar@example.com",
			.encrypted = 1,
			.spacebug = 1,
			.msgsize = 43,
			.authname = "baz",
			.logmsg = "received (NONE) encrypted message with SMTP space bug to <foo@example.com> from <> (authenticated as baz) from IP [::ffff:172.28.19.44] (43 bytes, 2 recipients)\n"
				"received (NONE) encrypted message with SMTP space bug to <bar@example.com> from <> (authenticated as baz) from IP [::ffff:172.28.19.44] (43 bytes, 2 recipients)\n",
			.envelope = envelope2,
			.envsize = sizeof(envelope2)
		},
		/* IP replacement */
		{
			.rcpt1 = "foo@[127.0.0.1]",
			.rcpt2 = "!bar@example.com",
			.msgsize = 47,
			.from = "baz@example.org",
			.logmsg = "received message to <foo@[127.0.0.1]> from <baz@example.org> from IP [::ffff:172.28.19.44] (47 bytes)\n",
			.envelope = envelope1ip,
			.envsize = sizeof(envelope1ip)
		},
		{
			.rcpt1 = NULL
		}
	};
	unsigned int i;
	SSL myssl;

	/* this doesn't really look right, but it works for now */
	memset(&myssl, 0, sizeof(myssl));

	strncpy(xmitstat.remoteip, "::ffff:172.28.19.44", sizeof(xmitstat.remoteip) - 1);
	xmitstat.remoteip[sizeof(xmitstat.remoteip) - 1] = '\0';

	liphost.s = "ip.example.com";
	liphost.len = strlen(liphost.s);

	for (i = 0; testpattern[i].rcpt1 != NULL; i++) {
		char rpipe[testpattern[i].envsize + 2];
		int fd[2];
		ssize_t r;

		TAILQ_INIT(&head);
		if (pipe(fd) != 0) {
			fprintf(stderr, "cannot create pipe\n");
			exit(ENOMEM);
		}
		xmitstat.spacebug = testpattern[i].spacebug;
		goodrcpt = 0;
		if (testpattern[i].encrypted)
			ssl = &myssl;
		else
			ssl = NULL;

		xmitstat.authname.s = (char *)testpattern[i].authname;
		xmitstat.authname.len = (testpattern[i].authname == NULL) ? 0 : strlen(testpattern[i].authname);
		xmitstat.mailfrom.s = (char *)testpattern[i].from;
		xmitstat.mailfrom.len = (testpattern[i].from == NULL) ? 0 : strlen(testpattern[i].from);

		create_rcpt(testpattern[i].rcpt1);
		create_rcpt(testpattern[i].rcpt2);

		queuefd_data = open(".", O_RDONLY | O_CLOEXEC);
		queuefd_hdr = fd[1];

		if (queue_envelope(testpattern[i].msgsize, testpattern[i].chunked) != 0) {
			fprintf(stderr, "%s[%u]: queue_envelope() failed, errno %i\n", __func__, i, errno);
			ret++;
		}

		r = read(fd[0], rpipe, testpattern[i].envsize + 2);
		if (r != testpattern[i].envsize) {
			fprintf(stderr, "%s[%u]: envelope of size %zi returned, but expected was %zu\n",
					__func__, i, r, testpattern[i].envsize);
			ret++;
		} else {
			if (memcmp(rpipe, testpattern[i].envelope, r) != 0) {
				fprintf(stderr, "%s[%u]: envelope did not match expected one\n", __func__, i);
				ret++;
			}
		}
		close(fd[0]);

		if (queuefd_data != -1) {
			fprintf(stderr, "%s[%u]: queue_envelope() did not reset queuefd_data\n", __func__, i);
			close(queuefd_data);
			ret++;
		}

		if (queuefd_hdr != -1) {
			fprintf(stderr, "%s[%u]: queue_envelope() did not reset queuefd_hdr\n", __func__, i);
			close(queuefd_hdr);
			ret++;
		}

		if (!TAILQ_EMPTY(&head)) {
			fprintf(stderr, "%s[%u]: queue_envelope() did not clear all recipients\n", __func__, i);
			ret++;
		}

		ret += check_logmsg(testpattern[i].logmsg);
	}

	return ret;
}

int
main(void)
{
	int ret = 0;

	testcase_setup_log_writen(tc_log_writen);

	ret += test_invalid_close();
	ret += test_invalid_write();
	ret += test_invalid_write2();
	ret += test_log_messages();

	return ret;
}
