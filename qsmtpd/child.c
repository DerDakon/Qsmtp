/** @file child.c
 * @brief helper functions for interacting with Qsmtpds child processes
 */

#include <qsmtpd/qsmtpd.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * @brief move the given descriptor to the target descriptor
 * @param p source descriptor
 * @param target the target descriptor of the read end
 * @return an error code or 0
 * @retval 0 everything is fine
 *
 * This will always clear the CLOEXEC flag from the target descriptor. The
 * source descriptor is left alone, assuming it will be closed because of
 * CLOEXEC anyway.
 */
int
fd_move(int p, int target)
{
	if (p == target) {
		int fl = fcntl(p, F_GETFD, 0);
		if (fl == -1)
			return errno;
		fl &= ~FD_CLOEXEC;
		if (fcntl(p, F_SETFD, fl) != 0)
			return errno;
		return 0;
	}

	if (dup2(p, target) < 0)
		return errno;

	return 0;
}

/**
 * @brief create a pipe where the writing end should belong to this process
 *
 * This behaves like pipe(), but will set the close-on-exec flag on the
 * pipe descriptors so a child process does not have to clean it up. This is
 * basically what pipe2() does on Linux.
 */
int
wpipe(int p[2])
{
#ifdef HAS_PIPE2
	return pipe2(p, O_CLOEXEC);
#else
	int r = pipe(p);

	if (r != 0)
		return r;

	if (fcntl(p[1], FD_CLOEXEC) == -1 || fcntl(p[0], FD_CLOEXEC) == -1) {
		int err = errno;
		(void) close(p[0]);
		(void) close(p[1]);
		errno = err;
		return -1;
	}

	return 0;
#endif
}
