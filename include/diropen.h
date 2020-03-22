/** \file diropen.h
 \brief declarations of functions for handling directories
 */
#ifndef DIROPEN_H
#define DIROPEN_H

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#if O_DIRECTORY == 0
#include <errno.h>
#endif /* O_DIRECTORY == 0 */

/**
 * @brief get a file descriptor for the given directory
 * @param base a filedescriptor to a base directory
 * @param dirname name of the directory
 * @return the file descriptor
 * @retval -1 the given name cannot be opened as directory (errno is set)
 *
 * This tries to open the given name as directory. In case this returns a
 * valid descriptor it is not guaranteed that the descriptor can be used for
 * anything else than being an anchor point for openat() calls.
 *
 * If dirname is an absolute filename base will be ignored.
 *
 * The CLOEXEC flag will be set for the descriptor if supported by the
 * underlying platform.
 */
static inline int __attribute__ ((nonnull (2)))
get_dirfd(int base, const char *dirname)
{
	int fd;

#ifdef O_PATH /* recent Linux */
	fd = openat(base, dirname, O_PATH | O_DIRECTORY | O_CLOEXEC);
#elif defined(O_SEARCH)
	fd = openat(base, dirname, O_SEARCH | O_DIRECTORY | O_CLOEXEC);
#else /* O_SEARCH */
	fd = openat(base, dirname, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
#endif /* O_PATH */

#if O_DIRECTORY == 0
	{
	struct stat st;
	/* in case O_DIRECTORY is not supported make sure that this really is
	 * a directory */
	if (fstat(fd, &st) != 0) {
		int e = errno;
		close(fd);
		errno = e;
		return -1;
	}

	if (!S_ISDIR(st.st_mode)) {
		close(fd);
		errno = ENOTDIR;
		return -1;
	}
	}
#endif /* O_DIRECTORY */

	return fd;
}

#endif /* DIROPEN_H */
