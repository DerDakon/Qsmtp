/** @file status.c
 * @brief functions to write delivery status information to qmail-rspawn
 */
#include <qremote/qremote.h>
#include <netio.h>

#include <string.h>
#include <unistd.h>

/* intentionally not in any header file, noone (but the testcases) should ever
 * need to access this. */
int statusfd = 1;

void
write_status_raw(const char *str, const size_t len)
{
	/* If the status can't be sent to qmail-rspawn immediately terminate
	 * the process. Worst case is that the mail was successfully sent but
	 * this can't be recorded, in which case the mail will just be sent
	 * again. */
	if (write(statusfd, str, len) < 0)
		net_conn_shutdown(shutdown_clean);
}

void
write_status(const char *str)
{
	write_status_raw(str, strlen(str));
	write_status_raw("\n", 2);
}

void
write_status_m(const char **strs, const unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count - 1; i++)
		write_status_raw(strs[i], strlen(strs[i]));
	write_status(strs[count - 1]);
}
