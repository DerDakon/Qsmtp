/** \file mmap.c
 \brief function to mmap a file
 */
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include "mmap.h"
#include "log.h"

void *
mmap_fd(int fd, off_t *len)
{
	int i;
	struct stat st;
	void *res;

	if ( (i = fstat(fd, &st)) )
		return NULL;
	if (!st.st_size)
		return NULL;

	*len = st.st_size;
	res = mmap(NULL, *len, PROT_READ, MAP_SHARED, fd, 0);

	return (res == MAP_FAILED) ? NULL : res;
}

void *
mmap_name(const char *fname, off_t *len, int *fd)
{
	void *buf;

	*fd = open(fname, O_RDONLY);

	if (*fd < 0)
		return NULL;

	while (flock(*fd, LOCK_SH)) {
		if (errno != EINTR) {
			int i;

			log_write(LOG_WARNING, "cannot lock input file");
			do {
				i = close(*fd);
			} while ((i < 0) && (errno == EINTR));
			errno = ENOLCK;	/* not the right error code, but good enough */
			return NULL;
		}
	}

	buf = mmap_fd(*fd, len);

	if (buf == NULL) {
		int i;

		flock(*fd, LOCK_UN);
		do {
			i = close(*fd);
		} while ((i < 0) && (errno == EINTR));
	}

	return buf;
}
