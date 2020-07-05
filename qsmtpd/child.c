/** @file child.c
 * @brief helper functions for interacting with Qsmtpds child processes
 */

#include <qsmtpd/qsmtpd.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * @brief move the read end of the pipe to the target descriptor
 * @param p both ends of the pipe
 * @param target the target descriptor of the read end
 * @return an error code or 0
 * @retval 0 everything is fine
 *
 * This will move the read end of the pipe to target, closing the old
 * descriptor afterwards. The write end is assumed to have the CLOEXEC flag set
 * on it, so it is not touched here. This is intended to be called in the child
 * process directly after forking, but before execve().
 *
 * If the read end of the pair is already target this function does nothing.
 */
int
pipe_move(int p[2], int target)
{
	if (p[0] == target)
		return 0;

	if (dup2(p[0], target) < 0)
		return errno;
	if (close(p[0]) != 0)
		return errno;

	return 0;
}

/**
 * @brief create a pipe where the writing end should belong to this process
 *
 * This behaves like pipe(), but will set the close-on-exec flag on the
 * write end so a child process does not have to clean it up.
 */
int
wpipe(int p[2])
{
	int r = pipe(p);

	if (r != 0)
		return r;

	if (fcntl(p[1], FD_CLOEXEC) == -1) {
		int err = errno;
		(void) close(p[0]);
		(void) close(p[1]);
		errno = err;
		return -1;
	}

	return 0;
}
