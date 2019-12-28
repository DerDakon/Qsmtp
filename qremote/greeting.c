/** \file greeting.c
 * \brief function to parse the EHLO greeting response
 */

#include <qremote/greeting.h>

#include <log.h>
#include <netio.h>
#include <qremote/qremote.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>

unsigned long remotesize;
const char *auth_mechs;
char auth_mechs_copy[996];	/**< copy of the AUTH mechanisms supported by the remote host, to avoid malloc() */

static int
cb_size(const char *more)
{
	char *s;

	if (!*more)
		return 0;

	remotesize = strtoul(more, &s, 10);
	return *s;
}

static int
cb_auth(const char *more)
{
	while (*more == ' ')
		more++;

	if (*more != '\0') {
		/* detect any 8bit or unprintable character here */
		const char *cur = more;
		while (*cur) {
			if ((*cur < 32) || (*cur >= 127))
				return -1;
			cur++;
		}

		/* Add a space at the beginning and the end. This allows lookups
		 * of any item as strstr(auth_mechs, " item ") without special
		 * cases. */
		auth_mechs_copy[0] = ' ';
		strncpy(auth_mechs_copy + 1, more, sizeof(auth_mechs_copy) - 3);
		auth_mechs_copy[sizeof(auth_mechs_copy) - 3] = '\0';
		size_t len = strlen(auth_mechs_copy);
		auth_mechs_copy[len++] = ' ';
		auth_mechs_copy[len] = '\0';

		auth_mechs = auth_mechs_copy;
	}

	return 0;
}

static int
cb_utf8(const char *more __attribute__ ((unused)))
{
	/* there are no parameters yet, but these must be ignored to be forward compatible */
	return 0;
}

int
esmtp_check_extension(const char *input)
{
	struct smtpexts {
		const char *name;
		unsigned int len;	/* strlen(name) */
		int (*func)(const char *more);	/* used to handle arguments to this extension, NULL if no arguments allowed */
	} extensions[] = {
		{ .name = "SIZE",	.len = 4,	.func = cb_size	}, /* 0x01 */
		{ .name = "PIPELINING",	.len = 10,	.func = NULL	}, /* 0x02 */
		{ .name = "STARTTLS",	.len = 8,	.func = NULL	}, /* 0x04 */
		{ .name = "8BITMIME",	.len = 8,	.func = NULL	}, /* 0x08 */
		{ .name = "AUTH",	.len = 4,	.func = cb_auth	}, /* 0x10 */
		{ .name = "SMTPUTF8",	.len = 8,	.func = cb_utf8	}, /* 0x20 */
#ifdef CHUNKING
		{ .name = "CHUNKING",	.len = 8,	.func = NULL	}, /* 0x40 */
#endif
		{ .name = NULL }
	};
	int j = 0;

	while (extensions[j].name) {
		/* match beginning */
		if (strncasecmp(input, extensions[j].name, extensions[j].len) != 0) {
			j++;
			continue;
		}

		/* check if the match is the entire line or arguments follow */
		if ((input[extensions[j].len] == '\0') || (input[extensions[j].len] == ' ')) {
			if (extensions[j].func)
				return extensions[j].func(input + extensions[j].len) ? -1 : (1 << j);
			else
				/* all entries that do not define a callback do not accept
				 * arguments, i.e. an argument here is an error. */
				return  (input[extensions[j].len] == '\0') ? (1 << j) : -1;
		}
		j++;
	}

	return 0;
}

static void
errmsg_syntax(const char *phase)
{
	const char *logmsg[] = { "syntax error in ", phase, "response \"",
			linein.s, "\" from ", rhost, NULL };

	log_writen(LOG_WARNING, logmsg);
}

int
greeting(void)
{
	const char *cmd[] = { "EHLO ", heloname.s, NULL };
	int ret = 0;
	int err = 0;

	net_writen(cmd);
	int s = netget(0);		/* SMTP status */
	if (s < 0)
		return s;
	while (linein.s[3] == '-') {
		int t = netget(0);
		if (s != t) {
			if (t < 0) {
				/* only log one error per connection */
				if (err == 0)
					errmsg_syntax(cmd[0]);
				return t;
			}
			err = 1;
		} else if ((s == 250) && (err == 0)) {
			int ext = esmtp_check_extension(linein.s + 4);

			if (ext < 0) {
				errmsg_syntax(cmd[0]);
				err = 1;
			} else {
				ret |= ext;
			}
		}
	}

	if (err != 0)
		return -EINVAL;
	if (s == 250)
		return ret;

	/* EHLO failed, try HELO */
	cmd[0] = "HELO ";
	net_writen(cmd);
	s = netget(0);
	if (s < 0) {
		errmsg_syntax(cmd[0]);
		return s;
	}
	while (linein.s[3] == '-') {
		int t = netget(0);
		if (t < 0) {
			errmsg_syntax(cmd[0]);
			return t;
		}
		if (t != s)
			err++;
	}

	if ((err == 0) && (s == 250))
		return 0;
	else if ((err == 0) && (s >= 400) && (s <= 599))
		return -EDONE;
	else
		return -EINVAL;
}
