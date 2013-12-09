/** \file greeting.c
 * \brief function to parse the EHLO greeting response
 */

#include <qremote/greeting.h>

#include <stdlib.h>
#include <string.h>

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
		size_t len;
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
		len = strlen(auth_mechs_copy);
		auth_mechs_copy[len++] = ' ';
		auth_mechs_copy[len] = '\0';

		auth_mechs = auth_mechs_copy;
	}

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
#ifdef CHUNKING
		{ .name = "CHUNKING",	.len = 8,	.func = NULL	}, /* 0x20 */
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
