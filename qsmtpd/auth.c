#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include "qsmtpd.h"
#include "sstring.h"
#include "netio.h"
#include "base64.h"
#include "log.h"

const char *tempnoauth = "454 4.3.0 AUTH temporaryly not available\r\n";

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

static int err_authabrt(void)
{
	return netwrite("501 5.0.0 auth exchange cancelled\r\n") ? errno : EDONE;
}

static int err_input(void)
{
	if (!netwrite("501 5.5.4 malformed auth input\r\n"))
		errno = EDONE;
	return -1;
}

static string authin;
static string user;
static string pass;
static string resp;

static int
authgetl(void) {
	int i;
	int nfirst = 0;	/* if this is the first loop: start at offset 0 */

	STREMPTY(authin);
	do {
		char *s;

		/* to avoid calling realloc for every byte we alloc and
		 * read in chunks of 64 byte */
		s = realloc(authin.s, authin.len + 64);

		if (!s) {
			free(authin.s);
			return -1;
		}
		authin.s = s;

		/* read the next 64 bytes */
		i = readinput(authin.s + authin.len - nfirst, 64 + nfirst);
		nfirst = 1;
		authin.len += i;
	} while (authin.s[authin.len - 1] != '\n');

	if (--authin.len)
		if (authin.s[authin.len - 1] == '\r')
			--authin.len;

	if ((*authin.s == '*') && (authin.len == 1)) {
		free(authin.s);
		errno = err_authabrt();
		return -1;
	}
	authin.s[authin.len] = '\0';
	if (authin.len == 0) {
		free(authin.s);
		return err_input();
	}
	return authin.len;
}

#define WRITE(a,b) if (write(pi[1], (a), (b)) < 0) { fun = err_write; goto out; }

static int
authenticate(void)
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
	switch(child = fork()) {
		case -1:	return err_fork();
		case 0:		while (close(pi[1])) {
					if (errno != EINTR)
						_exit(1);
				}
				if (pi[0] != 3) {
					if (dup2(pi[0],3)) {
						_exit(1);
					}
				}
				sa.sa_handler = SIG_DFL;
				sigemptyset(&(sa.sa_mask));
				sigaction(SIGPIPE, &sa, NULL);
				execlp(auth_check, auth_check, auth_sub, NULL);
				_exit(1);
	}
	while (close(pi[0])) {
		if (errno != EINTR)
			goto out;
	}

	WRITE(user.s, user.len + 1);
	WRITE(pass.s, pass.len + 1);
	/* make sure not to leak password */
	memset(pass.s, 0, pass.len);
	WRITE(resp.s, resp.len);
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
	/* make sure not to leak password */
	memset(pass.s, 0, pass.len);
	free(pass.s);
	free(resp.s);
	if (fun) {
		/* only free user.s here, it will be copied to
		 * xmitstat.authname.s on success */
		free(user.s);
		return fun();
	}
	return 0; /* yes */
}

static int
auth_login(void)
{
	int r;

	if (linelen > 11) {
		if ( (r = b64decode(linein + 11, linelen - 11, &user)) > 0)
			return err_input();
	} else {
		if (netwrite("334 VXNlcm5hbWU6\r\n")) /* Username: */
			return -1;
		if (authgetl() < 0)
			return -1;
		if ( (r = b64decode(authin.s, authin.len, &user) > 0) )
			goto err_input;
		free(authin.s);
	}
	if (r < 0)
		return r;

	if (netwrite("334 UGFzc3dvcmQ6\r\n")) /* Password: */
		goto err;

	if (authgetl() < 0)
		goto err;
	r = b64decode(authin.s, authin.len, &pass);
	memset(authin.s, 0, authin.len);
	free(authin.s);
	if (r > 0) {
		goto err_input;
	} else if (r < 0) {
		goto err;
	}

	if (!user.len || !pass.len)
		goto err;
	return authenticate();  
err_input:
	err_input();
err:
	free(user.s);
	memset(pass.s, 0, pass.len);
	free(pass.s);
	return -1;
}

static int
auth_plain(void)
{
	int r;
	unsigned int id = 0;
	string slop;

	STREMPTY(slop);

	if (linelen > 11) {
		if ( (r = b64decode(linein + 11, linelen - 11, &slop) > 0))
			return err_input();
	} else {
		if ((r = netwrite("334 \r\n")))
			return r;
		if ((r = authgetl()) < 0)
			return r;
		r = b64decode(authin.s, authin.len, &slop);
		free(authin.s);
		if (r > 0)
			return err_input();
	}
	if (r < 0) {
		return r;
	}
	while (slop.s[id])
		id++; /* ignore authorize-id */

	if (slop.len > id + 1) {
		char *s = slop.s + id + 1;
		/* one byte longer so we can also copy the trailing '\0' */
		r = newstr(&user, strlen(s) + 1);
		if (r)
			goto err;
		memcpy(user.s, s, user.len);
		if (slop.len > id + user.len + 1) {
			s += user.len;

			r = newstr(&pass, strlen(s) + 1);
			if (r)
				goto err;
			memcpy(pass.s, s, pass.len);
			pass.len--;
		}
		user.len--;
	}
	if (!user.len || !pass.len) {
		memset(pass.s, 0, pass.len);
		free(pass.s);
		err_input();
		goto err;
	}

	return authenticate();
err:
	free(user.s);
	free(slop.s);
	return -1;
}

#ifdef AUTHCRAM
static int
auth_cram(void)
{
	int i, r;
	unsigned int k, l, m;
	char *s, *t;
	const char *netmsg[] = { "334 ", NULL, NULL };
	string slop;
	char unique[83];

	t = ultostr(getpid());
	if (!t)
		return -1;
	m = strlen(t);
	memcpy(unique, t, m);
	free(t);
	unique[m++] = '.';
	s = unique + m;
	t = ultostr(time(NULL));
	if (!t)
		return -1;
	m = strlen(t);
	memcpy(s, t, m);
	free(t);
	s += m;
	*s++ = '@';

	/* (s - unique) is strlen(unique) but faster (and unique is not '\0'-terminated here!) */
	k = (s - unique);
	m = strlen(auth_host);
	/* '<' + unique + auth_host + '>'+ '\0' */
	l = 1 + k + m + 1 + 1;
	if ( (r = newstr(&pass, l)) )
		return r;
	pass.s[0] = '<';
	memcpy(pass.s + 1, unique, k);
	memcpy(pass.s + 1 + k, auth_host, m);
	pass.s[1 + k + m] = '>';
	pass.s[1 + k + m + 1] = '\0';
	if (b64encode(&pass, &slop) < 0)
		goto err;

	netmsg[1] = slop.s;
	if (net_writen(netmsg))
		goto err;
	free(slop.s);
	STREMPTY(slop);

	if (authgetl() < 0)
		goto err;
	r = b64decode(authin.s, authin.len, &slop);
	free(authin.s);
	if (r > 0) {
		err_input();
		goto err;
	} else if (r < 0) {
		goto err;
	}

	s = strchr(slop.s, ' ');
	if (!s) {
		err_input();
		goto err;
	}
	i = (s - slop.s);
	while (*s == ' ')
		s++;
	slop.s[i] = 0;

	if (newstr(&user, i))
		goto err;
	k = strlen(s);
	if ((r = newstr(&resp, k))) {
		free(user.s);
		goto err;
	}
	memcpy(user.s, slop.s, i + 1);
	memcpy(resp.s, s, k + 1);

	if (!user.len || !resp.len) {
		free(resp.s);
		err_input();
		goto err;
	}
	free(slop.s);
	return authenticate();
err:
	memset(slop.s, 0, slop.len);
	free(slop.s);
	/* don't need to memset pass here: it contains only our random challenge */
	free(pass.s);
	return -1;
}
#endif

static struct authcmd {
	char *text;
	int (*fun)(void);
} authcmds[] = {
	{	.text = "login",	.fun = auth_login },
	{	.text = "plain",	.fun = auth_plain },
#ifdef AUTHCRAM
	{	.text = "cram-md5",	.fun = auth_cram },
#endif
	{	.text = NULL,}
};

int
smtp_auth(void)
{
	int i;
	char *type = linein + 5;

	if (xmitstat.authname.len)
		return 1;

	if (!auth_host)
		return netwrite(tempnoauth) ? -1 : EBOGUS;

	STREMPTY(user);
	STREMPTY(pass);
	STREMPTY(resp);
	STREMPTY(authin);

	for (i = 0; authcmds[i].text; i++) {
		if (!strncasecmp(authcmds[i].text, type, strlen(authcmds[i].text))) {
			switch (authcmds[i].fun()) {
				case 0:	xmitstat.authname.s = user.s;
					xmitstat.authname.len = user.len;
					return netwrite("235 2.0.0 ok, go ahead\r\n") ? errno : 0;
				case 1:	return netwrite("535 5.7.0 authorization failed\r\n") ? errno : EDONE;
				case -1: return errno;
			}
		}
	}
	return netwrite("504 5.5.1 Unrecognized authentication type.\r\n") ? errno : EDONE;
}
