#include <qremote/mime.h>

#include <netio.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

void
write_status(const char *str)
{
	puts(str);
}

void
net_conn_shutdown(const enum conn_shutdown_type sd_type)
{
	if (sd_type == shutdown_abort)
		exit(0);
	else
		exit(EINVAL);
}

int
main(int argc, char **argv)
{
	char buf[256];
	cstring line, boundary;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s boundary\n", argv[0]);
		return -1;
	}

	snprintf(buf, sizeof(buf), "Content-Type: multipart/mixed; boundary=%s", argv[1]);

	line.s = buf;
	line.len = strlen(line.s);

	int r = is_multipart(&line, &boundary);

	fprintf(stderr, "is_multipart() returned %i\n", r);

	/* this test should be used for the invalid cases that terminate the
	 * process, use mime_test.c for the other ones. */
	return -1;
}
