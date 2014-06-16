#include <qsmtpd/queue.h>

#include <qsmtpd/qsmtpd.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct xmitstat xmitstat;
unsigned int goodrcpt;
string liphost;
static struct smtpcomm command;
struct smtpcomm *current_command = &command;

pid_t
fork_clean()
{
	exit(EFAULT);
}

void
freedata(void)
{
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

	return 0;
}

static int
test_invalid_write(void)
{
	int ret = 0;
	int r;

	queuefd_data = open(".", O_RDONLY);
	queuefd_hdr = open(".", O_RDONLY);

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

	return ret;
}

static int
test_invalid_write2(void)
{
	int ret = 0;
	int r;

	queuefd_data = open(".", O_RDONLY);
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

	return ret;
}

int
main(void)
{
	int ret = 0;

	ret += test_invalid_close();
	ret += test_invalid_write();
	ret += test_invalid_write2();

	return ret;
}
