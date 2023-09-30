/** \file qp.c
 \brief program to convert a file to quoted-printable

 qp converts the contents of the given filename to quoted-printable,
 using Qremotes recoding engine. The result will be written to stdout.
 */

#include <fmt.h>
#include <netio.h>
#include <mmap.h>
#include <qremote/qrdata.h>
#include <sstring.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern void send_qp(const char *, const off_t);
unsigned int smtpext;
struct string heloname;
int in_data;

void quit(void)
{
}

void write_status(const char *str)
{
	puts(str);
}

void write_status_m(const char **strs, const unsigned int count)
{
	for (unsigned int i = 0; i < count - 1; i++)
		fputs(strs[i], stdout);
	puts(strs[count - 1]);
}

void net_conn_shutdown(const enum conn_shutdown_type sd_type __attribute__ ((unused)))
{
	exit(0);
}

int net_writen(const char *const *s)
{
	int i = 0, rc = 0;

	while (s[i] && (rc >= 0)) {
		rc = write(1, s[i], strlen(s[i]));
		i++;
	}
	if (rc >= 0)
		rc = write(1, "\r\n", 2);
	return (rc >= 0) ? 0 : -errno;
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

void ultostr(const unsigned long u, char *res)
{
	snprintf(res, ULSTRLEN, "%lu", u);
}

char lineinbuf[10];
struct string linein = {
	.s = lineinbuf
};

int netnwrite(const char *s, size_t l)
{
	return write(1, s, l);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fputs("Usage: qp filename\n", stderr);
		return 1;
	}

	heloname.s = "caliban.sf-tec.de";
	heloname.len = strlen(heloname.s);

	int fd = open(argv[1], O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return errno;

	msgdata = mmap_fd(fd, &msgsize);

	if (msgdata == NULL)
		return errno;

	send_data(need_recode(msgdata, msgsize));

	munmap((void *)msgdata, msgsize);

	return 0;
}
