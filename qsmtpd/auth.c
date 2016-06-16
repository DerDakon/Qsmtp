/** \file auth.c
 \brief functions for SMTP AUTH
 */

#include <qsmtpd/qsauth.h>
#include <qsmtpd/qsauth_backend.h>

#include <base64.h>
#include <control.h>
#include <fmt.h>
#include <log.h>
#include <netio.h>
#include <qsmtpd/antispam.h>
#include <qsmtpd/qsmtpd.h>
#include <sstring.h>
#include <tls.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

const char *tempnoauth = "454 4.5.0 AUTH temporaryly not available\r\n";
static const char *auth_host;			/**< hostname for auth */

static int err_input(void)
{
	tarpit();
	if (!netwrite("501 5.5.4 malformed auth input\r\n"))
		return -EDONE;
	return -errno;
}

static int err_base64(void)
{
	tarpit();
	if (!netwrite("501 5.5.2 base64 decoding error\r\n"))
		errno = EDONE;
	return -1;
}

/**
 * @brief read in AUTH line
 * @param authin buffer to hold authenication data
 * @returns if reading data was successful
 * @retval 0 AUTH line was read into authin
 * @retval -1 error (errno is set)
 */
static int
authgetl(string *authin)
{
	STREMPTY(*authin);
	do {
		int i;
		char *s;

		/* to avoid calling realloc for every byte we alloc and
		 * read in chunks of 64 byte */
		s = realloc(authin->s, authin->len + 64);

		if (!s) {
			free(authin->s);
			return -1;
		}
		authin->s = s;

		/* read the next 64 bytes */
		i = net_readline(64, authin->s + authin->len);
		if (i < 0) {
			free(authin->s);
			return -1;
		}
		authin->len += i;
	} while (authin->s[authin->len - 1] != '\n');

	if (--authin->len) {
		if (authin->s[authin->len - 1] == '\r')
			--authin->len;

		if ((authin->len == 1) && (*authin->s == '*')) {
			free(authin->s);
			if (!netwrite("501 5.0.0 auth exchange cancelled\r\n"))
				errno = EDONE;
			return -1;
		}
		authin->s[authin->len] = '\0';
	}

	if (authin->len == 0) {
		free(authin->s);
		errno = -err_input();
		return -1;
	}
	return 0;
}

static int
auth_login(struct string *user)
{
	string authin, pass;
	int r;

	if (linein.len > 11) {
		r = b64decode(linein.s + 11, linein.len - 11, user);
	} else {
		if (netwrite("334 VXNlcm5hbWU6\r\n")) /* Username: */
			return -1;
		if (authgetl(&authin) < 0)
			return -1;
		r = b64decode(authin.s, authin.len, user);
		free(authin.s);
	}
	if (r > 0) {
		return err_base64();
	} else if (r < 0) {
		errno = -r;
		return -1;
	}

	if (netwrite("334 UGFzc3dvcmQ6\r\n")) /* Password: */
		goto err;

	if (authgetl(&authin) < 0)
		goto err;
	r = b64decode(authin.s, authin.len, &pass);
	memset(authin.s, 0, authin.len);
	free(authin.s);
	if (r > 0) {
		err_base64();
		goto err;
	} else if (r < 0) {
		errno = -r;
		goto err;
	}

	if (!user->len || !pass.len) {
		if (pass.s != NULL) {
			memset(pass.s, 0, pass.len);
			free(pass.s);
		}
		errno = -err_input();
		goto err;
	}
	r = auth_backend_execute(user, &pass, NULL);
	memset(pass.s, 0, pass.len);
	free(pass.s);
	if (r != 0)
		free(user->s);
	if (r < 0) {
		errno = -r;
		return -1;
	}
	return r;
err:
	free(user->s);
	return -1;
}

static int
auth_plain(struct string *user)
{
	int r;
	unsigned int id = 0;
	string slop = STREMPTY_INIT, pass = STREMPTY_INIT;

	if (linein.len > 11) {
		r = b64decode(linein.s + 11, linein.len - 11, &slop);
	} else {
		string authin;

		if ((r = netwrite("334 \r\n")))
			return r;
		if (authgetl(&authin) < 0)
			return -1;
		r = b64decode(authin.s, authin.len, &slop);
		free(authin.s);
	}
	if (r > 0) {
		return err_base64();
	} else if (r < 0) {
		errno = -r;
		return -1;
	}

	while (slop.s[id])
		id++; /* ignore authorize-id */

	id++; /* skip the \0 delimiter between authorize-id and username */

	if (slop.len > id) {
		user->s = slop.s + id;
		user->len = strlen(user->s);
		if (slop.len > id + user->len + 1) {
			pass.s = user->s + user->len + 1;
			pass.len = strlen(pass.s);
		}
	}
	if (!user->len || !pass.len) {
		errno = -err_input();
		memset(slop.s, 0, slop.len);
		free(slop.s);
		return -1;
	}

	r = auth_backend_execute(user, &pass, NULL);
	memset(pass.s, 0, pass.len);
	if (r != 0) {
		free(slop.s);
		if (r < 0) {
			errno = -r;
			return -1;
		}
	} else {
		char *tmp;
		memmove(slop.s, user->s, user->len + 1);
		tmp = realloc(slop.s, user->len + 1);
		if (tmp == NULL)
			user->s = slop.s;
		else
			user->s = tmp;
	}
	return r;
}

#ifdef AUTHCRAM
static int err_no_initial(void)
{
	tarpit();
	if (!netwrite("501 5.7.0 authentication mechanism does not support initial response\r\n"))
		errno = EDONE;
	return -1;
}

static int
auth_cram(struct string *user)
{
	size_t i;
	int r;
	unsigned int k, l, m;
	char *s, t[ULSTRLEN];
	const char *netmsg[] = { "334 ", NULL, NULL };
	string authin, challenge, slop, resp;
	char unique[83];

	if (linein.len != strlen("AUTH CRAM-MD5"))
		return err_no_initial();

	ultostr(getpid(), t);
	m = strlen(t);
	memcpy(unique, t, m);
	unique[m++] = '.';
	s = unique + m;
	ultostr(time(NULL), t);
	m = strlen(t);
	memcpy(s, t, m);
	s += m;
	*s++ = '@';

	STREMPTY(challenge);

	/* (s - unique) is strlen(unique) but faster (and unique is not '\0'-terminated here!) */
	k = (s - unique);
	m = strlen(auth_host);
	/* '<' + unique + auth_host + '>'+ '\0' */
	l = 1 + k + m + 1 + 1;
	if ( (r = newstr(&challenge, l)) )
		return r;
	challenge.s[0] = '<';
	memcpy(challenge.s + 1, unique, k);
	memcpy(challenge.s + 1 + k, auth_host, m);
	challenge.s[1 + k + m] = '>';
	challenge.s[1 + k + m + 1] = '\0';
	r = b64encode(&challenge, &slop, -1);
	if (r < 0) {
		errno = -r;
		goto err;
	}

	netmsg[1] = slop.s;
	if (net_writen(netmsg))
		goto err;
	free(slop.s);
	STREMPTY(slop);

	if (authgetl(&authin) < 0)
		goto err;
	r = b64decode(authin.s, authin.len, &slop);
	free(authin.s);
	if (r > 0) {
		STREMPTY(slop);
		err_base64();
		goto err;
	} else if (r < 0) {
		errno = -r;
		goto err;
	}

	s = strchr(slop.s, ' ');
	i = (s - slop.s);

	if ((s == NULL) || (i == 0)) {
		errno = -err_input();
		goto err;
	}

	while (*s == ' ')
		s++;
	resp.len = strlen(s);
	if (resp.len != 32) {
		errno = -err_input();
		goto err;
	}

	for (r = 31; r >= 0; r--) {
		if (!(((s[r] >= '0') && (s[r] <= '9')) ||
				((s[r] >= 'a') && (s[r] <= 'f')) ||
				((s[r] >= 'A') && (s[r] <= 'F')))) {
			errno = -err_input();
			goto err;
		}
	}

	user->s = slop.s;
	user->len = i;
	slop.s[i] = '\0';
	resp.s = s;

	r = auth_backend_execute(user, &challenge, &resp);
	free(challenge.s);
	if (r != 0) {
		free(slop.s);
	} else {
		/* truncate the username to what is really needed */
		char *tmp = realloc(user->s, user->len + 1);

		if (tmp != NULL)
			user->s = tmp;
		else
			/* if truncating failed just keep the old pointer,
			 * this just has extra stuff at the end. Clear that. */
			memset(resp.s, 0, resp.len);
	}

	if (r < 0) {
		errno = -r;
		return -1;
	}
	return r;
err:
	free(slop.s);
	free(challenge.s);
	return -1;
}
#endif

static struct authcmd {
	char *text;
	int (*fun)(struct string *);
} authcmds[] = {
	{	.text = "login",	.fun = auth_login },
	{	.text = "plain",	.fun = auth_plain },
#ifdef AUTHCRAM
	{	.text = "cram-md5",	.fun = auth_cram },
#endif
	{	.text = NULL,}
};

/**
 * check if user sends valid authentication
 *
 * @return 0 if user is successfully authenticated, error code else
 */
int
smtp_auth(void)
{
	int i;
	char *type = linein.s + 5;

	if (xmitstat.authname.len || !auth_permitted())
		return 1;

	STREMPTY(xmitstat.authname);

	for (i = 0; authcmds[i].text; i++) {
		if (!strncasecmp(authcmds[i].text, type, strlen(authcmds[i].text))) {
			switch (authcmds[i].fun(&xmitstat.authname)) {
			case 0:
				return netwrite("235 2.7.0 ok, go ahead\r\n") ? errno : 0;
			case 1:
				STREMPTY(xmitstat.authname);
				sleep(5);
				return netwrite("535 5.7.8 authorization failed\r\n") ? errno : EDONE;
			case -1:
				STREMPTY(xmitstat.authname);
				return errno;
			}
		}
	}
	return netwrite("504 5.5.4 Unrecognized authentication type.\r\n") ? errno : EDONE;
}

/**
 * @brief return a list of all enabled auth types
 *
 * @return string of enabled auth types
 * @retval NULL out of memory or AUTH currently not permitted
 *
 * The returned memory is allocated and has to be freed by the caller.
 *
 * The returned string will contain a trailing CRLF pair.
 */
char *
smtp_authstring(void)
{
	size_t conflen, slen, confpos, wpos;
	char *confbuf, *ret, *tmp;
	unsigned int i;
	uint8_t usedtype;	/* make sure this is big enough to hold all auth types */

	/* AUTH is currently not permitted */
	if (!auth_permitted())
		return NULL;

	conflen = lloadfilefd(openat(controldir_fd, "authtypes", O_RDONLY | O_CLOEXEC), &confbuf, 3);

	if (conflen == (size_t) -1)
		return NULL;

	i = 0;
	slen = 1;
	while (authcmds[i].text != NULL) {
		/* +1 for the leading space of every entry */
		slen += strlen(authcmds[i].text) + 1;
		i++;
	}

	/* +3 for trailing CRLF\0 */
	ret = malloc(slen + 3);
	if (ret == NULL) {
		free(confbuf);
		return NULL;
	}

	if (conflen == 0) {
		wpos = 0;
		i = 0;

		while (authcmds[i].text != NULL) {
			ret[wpos++] = ' ';
			strcpy(ret + wpos, authcmds[i].text);
			wpos += strlen(authcmds[i].text);
			i++;
		}

		ret[wpos] = '\r';
		ret[wpos + 1] = '\n';
		ret[wpos + 2] = '\0';

		/* ret[0] is a space anyway */
		while (wpos > 0) {
			ret[wpos] = toupper(ret[wpos]);
			wpos--;
		}

		return ret;
	}

	confpos = 0;
	usedtype = 0;
	wpos = 0;
	while (confpos < conflen) {
		int found = 0;

		i = 0;
		while (authcmds[i].text != NULL) {
			if (strcasecmp(authcmds[i].text, confbuf + confpos) == 0) {
				if (usedtype & (1 << i)) {
					const char *logmsg[] = {"error: duplicate auth type \"",
								confbuf + confpos,
								"\" found in control/authtypes", NULL};
					log_writen(LOG_ERR, logmsg);
					found = 1;
					break;
				}
				found = 1;
				usedtype |= (1 << i);
				ret[wpos++] = ' ';
				strcpy(ret + wpos, authcmds[i].text);
				while (ret[wpos]) {
					ret[wpos] = toupper(ret[wpos]);
					wpos++;
				}
				break;
			}
			i++;
		}

		if (found == 0) {
			const char *logmsg[] = {"error: unknown auth type \"", confbuf + confpos,
						"\" found in control/authtypes", NULL};
			log_writen(LOG_ERR, logmsg);
		}
		confpos += strlen(confbuf + confpos) + 1;
	}

	free(confbuf);

	if (wpos == 0) {
		free(ret);
		errno = ENOENT;
		return NULL;
	}

	ret[wpos++] = '\r';
	ret[wpos++] = '\n';
	ret[wpos++] = '\0';

	tmp = realloc(ret, wpos);
	if (tmp == NULL)
		return ret;
	else
		return tmp;
}

int
auth_permitted(void)
{
	if (auth_host == NULL)
		return 0;

	if (sslauth && (ssl == NULL))
		return 0;

	return 1;
}

void
auth_setup(int argc, const char **argv)
{
	auth_host = NULL;

	if (argc == 1)
		return;

	if (domainvalid(argv[1])) {
		const char *msg[] = { "domainname for auth invalid: ", argv[1], NULL };

		log_writen(LOG_WARNING, msg);
		return;
	}

	if (auth_backend_setup(argc, argv) == 0)
		auth_host = argv[1];
}
