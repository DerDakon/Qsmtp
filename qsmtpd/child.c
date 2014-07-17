/** @file child.c
 * @brief helper functions for interacting with Qsmtpds child processes
 */

#include <qsmtpd/qsmtpd.h>

#include <errno.h>
#include <unistd.h>

/**
 * @brief move the read end of the pipe to the target descriptor
 * @param p both ends of the pipe
 * @param target the target descriptor of the read end
 * @return if everything went smooth
 * @retval 0 everything is fine
 *
 * This will move the read end of the pipe to target, closing both the write
 * end of the pipe and the old read end of the pipe. This is intended to be
 * called in the child process directly after forking, but before execve().
 */
int
pipe_move(int p[2], int target)
{
	if (close(p[1]) != 0)
		return errno;

	if (p[0] != target) {
		if (dup2(p[0], target) < 0)
			return errno;
		if (close(p[0]) != 0)
			return errno;
	}

	return 0;
}
