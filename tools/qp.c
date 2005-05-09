#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "qrdata.h"
#include "netio.h"
#include "sstring.h"

extern void send_qp(const char *, const q_off_t);
unsigned int smtpext;
struct string heloname;
int in_data;

void quit(void) { return; }
int net_writen(const char *const *a __attribute__ ((unused)))
{
	int i = 0, rc = 0;

	while (a[i] && (rc >= 0)) {
		rc = write(1, a[i], strlen(a[i]));
		i++;
	}
	write(1, "\r\n", 2);
	return (rc >= 0) ? 0 : rc;
}

int checkreply(const char *status __attribute__ ((unused)), const char **pre __attribute__ ((unused)),
					const int mask __attribute__ ((unused)))
{
	return 0;
}

void log_write(int loglevel __attribute__ ((unused)), const char *msg __attribute__ ((unused)))
{
}

int netget(void)
{
	return 354;
}

int netwrite(const char *a) {
	return netnwrite(a, strlen(a));
}

void ultostr(const unsigned long u, char *buf)
{
	snprintf(buf, ULSTRLEN, "%lu", u);
}

char linein[10];
size_t linelen;

int netnwrite(const char *buffer, size_t len)
{
	return write(1, buffer, len);
}

int main(int argc, char *argv[])
{
	int fd, i;
	struct stat st;

	if (argc != 2) {
		write(2, "Usage: qp filename\n", 19);
		return 1;
	}

	heloname.s = "caliban.sf-tec.de";
	heloname.len = strlen(heloname.s);

	fd = open(argv[1], O_RDONLY);

	if (fd < 0)
		return errno;

	i = fstat(fd, &st);
	if (i)
		return i;

	msgsize = st.st_size;
	msgdata = mmap(NULL, msgsize, PROT_READ, MAP_SHARED, fd, 0);

	if (msgdata == MAP_FAILED)
		return errno;

	send_data();

	return 0;
}
