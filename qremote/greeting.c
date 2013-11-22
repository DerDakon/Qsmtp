/** \file greeting.c
 * \brief function to parse the EHLO greeting response
 */

#include "greeting.h"

#include <stdlib.h>
#include <string.h>

unsigned long remotesize;

static int
cb_size(const char *more)
{
	char *s;
	
	if (!*more)
		return 0;
	
	remotesize = strtoul(more, &s, 10);
	return *s;
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
