/** @file status.c
 * @brief functions to write delivery status information to qmail-rspawn
 */

#include <qremote/qremote.h>
#include <netio.h>

#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

/* intentionally not in any header file, noone (but the testcases) should ever
 * need to access this. */
int statusfd = 1;

static void
write_status_vec(const struct iovec *data, int cnt)
{
	ssize_t slen = 0;
	for (int i = 0; i < cnt; i++)
		slen += data[i].iov_len;

	/* see write_status_raw() for reasoning */
	if (writev(statusfd, data, cnt) != slen)
		net_conn_shutdown(shutdown_clean);
}

void
write_status_raw(const char *str, const size_t len)
{
	/* If the status can't be sent to qmail-rspawn immediately terminate
	 * the process. Worst case is that the mail was successfully sent but
	 * this can't be recorded, in which case the mail will just be sent
	 * again. */
	if (write(statusfd, str, len) != (ssize_t)len)
		net_conn_shutdown(shutdown_clean);
}

void
write_status(const char *str)
{
	struct iovec data[] = {
		{
			.iov_base = (void*)str,
			.iov_len = strlen(str)
		},
		{
			.iov_base = "\n",
			.iov_len = 2
		}
	};

	write_status_vec(data, 2);
}

void
write_status_m(const char **strs, const unsigned int count)
{
	struct iovec *vectors = calloc(count + 1, sizeof(*vectors));

	if (vectors == NULL) {
		// fallback, less efficient
		for (unsigned int i = 0; i < count - 1; i++)
			write_status_raw(strs[i], strlen(strs[i]));
		write_status(strs[count - 1]);
	} else {
		for (unsigned int i = 0; i < count; i++) {
			vectors[i].iov_base = (void*)strs[i];
			vectors[i].iov_len = strlen(strs[i]);
		}
		vectors[count].iov_base = "\n";
		vectors[count].iov_len = 2;
		write_status_vec(vectors, count + 1);
		free(vectors);
	}
}
