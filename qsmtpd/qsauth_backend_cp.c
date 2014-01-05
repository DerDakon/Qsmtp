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
#include <unistd.h>
#include <sys/wait.h>

const char *auth_check;			/**< checkpassword or one of his friends for auth */
const char **auth_sub;			/**< subprogram to be invoked by auth_check (usually /bin/true) */

static int err_child(void)
{
	log_write(LOG_ERR, "auth child crashed");
	if (!netwrite(tempnoauth))
		errno = EDONE;
	return -1;
}

static int err_fork(void)
{
	log_write(LOG_ERR, "cannot fork auth");
	if (!netwrite(tempnoauth))
		errno = EDONE;
	return -1;
}

static int err_pipe(void)
{
	log_write(LOG_ERR, "cannot create pipe for authentication");
	if (!netwrite(tempnoauth))
		errno = EDONE;
	return -1;
}

static int err_write(void)
{
	log_write(LOG_ERR, "pipe error while authenticating");
	if (!netwrite(tempnoauth))
		errno = EDONE;
	return -1;
}

#define WRITE(a,b) if (write(pi[1], (a), (b)) < 0) { fun = err_write; goto out; }

int
auth_backend_execute(const struct string *user, const struct string *pass, const struct string *resp)
{
	pid_t child;
	int wstat;
	int pi[2];
	struct sigaction sa;
	int (*fun)(void) = NULL;

	if (pipe(pi) == -1) {
		fun = err_pipe;
		goto out;
	}
	switch(child = fork_clean()) {
	case -1:
		while ((close(pi[0]) < 0) && (errno == EINTR)) {}
		while ((close(pi[1]) < 0) && (errno == EINTR)) {}
		fun = err_fork;
		goto out;
	case 0:
		while (close(pi[1])) {
			if (errno != EINTR)
				_exit(1);
		}
		if (pi[0] != 3) {
			if (dup2(pi[0],3) < 0) {
				_exit(1);
			}
		}

		memset((char *)pass->s, 0, pass->len);
		free(pass->s);
		free(user->s);
		if (resp != NULL)
			free(resp->s);

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = SIG_DFL;
		sigemptyset(&(sa.sa_mask));
		sigaction(SIGPIPE, &sa, NULL);
		execlp(auth_check, auth_check, *auth_sub, NULL);
		_exit(1);
	}
	while (close(pi[0])) {
		if (errno != EINTR)
			goto out;
	}

	WRITE(user->s, user->len + 1);
	WRITE(pass->s, pass->len + 1);
	if (resp != NULL)
		WRITE(resp->s, resp->len);
	WRITE("", 1);
	while (close(pi[1])) {
		if (errno != EINTR)
			goto out;
	}

	while (waitpid(child, &wstat, 0) == -1) {
		if (errno != EINTR) {
			fun = err_child;
			goto out;
		}
	}
	if (!WIFEXITED(wstat)) {
		fun = err_child;
		goto out;
	}
	if (WEXITSTATUS(wstat)) {
		sleep(5);
		return 1;
	} /* no */
out:
	if (fun)
		return fun();

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
	auth_sub = ((const char **)argv) + 3;

	if (access(auth_check, X_OK) != 0) {
		const char *msg[] = { "checkpassword program '", auth_check,
				"' is not executable, error was: ",
				strerror(errno), NULL };

		log_writen(LOG_WARNING, msg);

		return -EACCES;
	}

	return 0;
}
