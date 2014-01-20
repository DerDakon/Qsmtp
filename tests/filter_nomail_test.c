#include <qsmtpd/userfilters.h>
#include <qsmtpd/userconf.h>
#include "test_io/testcase_io.h"

#include <qsmtpd/qsmtpd.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>

struct xmitstat xmitstat;
unsigned int goodrcpt;
struct recip *thisrecip;
const char **globalconf;

extern int cb_nomail(const struct userconf *ds, char **logmsg, int *t);

static int err;

static int
test_net_writen(const char * const * msg)
{
	const char errcode[] = "550 5.7.1 ";
	if (strncmp(*msg, errcode, strlen(errcode)) != 0) {
		err++;
		fprintf(stderr, "message did not begin with '550 5.7.1 ': %s\n", *msg);
	}

	return 0;
}

static const char *rejectmsg[] = {
	"5500 5.7.1 foobar", // third character is not a space or dash
	"550 abc", // no extended status code
	"200 2.0.0 foo", // no error code
	"550 5.7.1 good boy", // correct error code
	NULL
};

int main()
{
	char *logmsg;
	int t;
	struct userconf ds;
	int i;
	int r;
	int fd;

	testcase_setup_net_writen(test_net_writen);

	memset(&ds, 0, sizeof(ds));
	globalconf = NULL;

	ds.userpath.s = "./";
	ds.userpath.len = 2;

	for (i = 0; rejectmsg[i] != NULL; i++) {
		fd = creat("nomail", 0600);
		if (fd == -1) {
			fprintf(stderr, "cannot create file 'nomail'\n");
			return -1;
		}
		write(fd, rejectmsg[i], strlen(rejectmsg[i]));
		write(fd, "\n", 1);
		close(fd);

		t = -1;
		r = cb_nomail(&ds, &logmsg, &t);
		if ((r != 1) || (t != CONFIG_USER)) {
			fprintf(stderr, "nomail filter should reject, but output was r %i t %i\n", r, t);
			err++;
		}
	}

	fd = creat("nomail", 0600);
	if (fd == -1) {
		fprintf(stderr, "cannot create file 'nomail'\n");
		return -1;
	}
	close(fd);

	t = -1;
	r = cb_nomail(&ds, &logmsg, &t);
	if ((r != 2) || (t != CONFIG_USER)) {
		fprintf(stderr, "nomail filter should reject, but output was r %i t %i\n", r, t);
		err++;
	}

	unlink("nomail");
	t = -1;
	r = cb_nomail(&ds, &logmsg, &t);
	if (r != 0) {
		fprintf(stderr, "nomail filter should not reject without nomail file, but r was %i\n", r);
		err++;
	}

	return err;
}
