/** \file qsauth_backend_cp.c
 \brief checkpassword AUTH backend
 */

#include <qsmtpd/qsauth_backend.h>

#include <log.h>
#include <netio.h>
#include <qsmtpd/qsmtpd.h>

#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <sys/wait.h>
#include <unistd.h>

const char *auth_check;			/**< checkpassword or one of his friends for auth */
const char *auth_sub;			/**< subprogram to be invoked by auth_check (usually /bin/true) */
const char *auth_sub_arg;		/**< additional argument passed after subprogram */

static int err_child(void)
{
	log_write(LOG_ERR, "auth child crashed");
	if (!netwrite(tempnoauth))
		return -EDONE;
	return -errno;
}

static int err_fork(void)
{
	log_write(LOG_ERR, "cannot fork auth");
	if (!netwrite(tempnoauth))
		return -EDONE;
	return -errno;
}

static int err_pipe(void)
{
	log_write(LOG_ERR, "cannot create pipe for authentication");
	if (!netwrite(tempnoauth))
		return -EDONE;
	return -errno;
}

static int err_write(void)
{
	log_write(LOG_ERR, "pipe error while authenticating");
	if (!netwrite(tempnoauth))
		return -EDONE;
	return -errno;
}

#define WRITE(a,b) \
	do { \
		if (write(pi[1], (a), (b)) == -1) { \
			return err_write(); \
		} \
	} while (0)

int
auth_backend_execute(const struct string *user, const struct string *pass, const struct string *resp)
{
	pid_t child;
	int wstat;
	int pi[2];

	if (wpipe(pi) == -1)
		return err_pipe();

	switch (child = fork_clean()) {
	case -1:
		close(pi[0]);
		close(pi[1]);
		return err_fork();
	case 0:
		{
		sigset_t mask;

		if (fd_move(pi[0], 3) != 0)
			_exit(1);

		sigemptyset(&mask);
		sigaddset(&mask, SIGPIPE);
		if (sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0)
			_exit(1);

		execlp(auth_check, auth_check, auth_sub, auth_sub_arg, NULL);
		_exit(1);
		}
	}
	if (close(pi[0]) != 0)
		return err_write();

	WRITE(user->s, user->len + 1);
	WRITE(pass->s, pass->len + 1);
	if (resp != NULL)
		WRITE(resp->s, resp->len);
	WRITE("", 1);

	if (close(pi[1]) != 0)
		return err_write();

	if (waitpid(child, &wstat, 0) == -1)
		return err_child();
	if (!WIFEXITED(wstat))
		return err_child();

	if (WEXITSTATUS(wstat))
		return 1; /* no */

	return 0; /* yes */
}

int
auth_backend_setup(int argc, const char **argv)
{
	if (argc < 4) {
		log_write(LOG_ERR, "invalid number of parameters given");
		return -EINVAL;
	}

	auth_check = argv[2];
	auth_sub = argv[3];
	auth_sub_arg = argc > 4 ? argv[4] : NULL;

	if (access(auth_check, X_OK) != 0) {
		const char *msg[] = { "checkpassword program '", auth_check,
				"' is not executable, error was: ",
				strerror(errno), NULL };

		log_writen(LOG_WARNING, msg);

		return -EACCES;
	}

	return 0;
}
