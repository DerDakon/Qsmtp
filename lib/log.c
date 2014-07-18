/** \file log.c
 \brief syslog interface
 */

#include <log.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

/**
 * combine line and write it to syslog
 *
 * @param priority syslog priority
 * @param s array of log messages
 */
void
log_writen(int priority, const char **s)
{
	unsigned int j;
	size_t i = 0;
	char *buf;

	for (j = 0; s[j]; j++)
		i += strlen(s[j]);
	buf = malloc(i + 2);
	if (!buf) {
#ifdef USESYSLOG
		syslog(LOG_ERR, "out of memory\n");
#endif
#ifndef NOSTDERR
		write(2, "not enough memory for log message\n", 34);
#endif
		return;
	} else {
		i = 0;
		for (j = 0; s[j]; j++) {
			strcpy(buf + i, s[j]);
			i += strlen(s[j]);
		}
		buf[i++] = '\n';
		buf[i] = '\0';
	}
#ifdef USESYSLOG
	syslog(priority, "%s", buf);
#else
	(void)priority;
#endif
#ifndef NOSTDERR
	write(2, buf, i);
#endif
	free(buf);
}

/**
 * write single message to syslog
 *
 * @param priority syslog priority
 * @param s message to write
 * @see log_writen
 */
inline void
log_write(int priority, const char *s)
{
	const char *t[] = {s, NULL};
	log_writen(priority, t);
}
