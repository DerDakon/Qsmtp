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
	size_t i = 0;

	for (unsigned int j = 0; s[j]; j++)
		i += strlen(s[j]);
	char *buf = malloc(i + 2);
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
		for (unsigned int j = 0; s[j]; j++) {
			strcpy(buf + i, s[j]);
			i += strlen(s[j]);
		}
		buf[i++] = '\n';
		buf[i] = '\0';
	}
	log_write(priority, buf);
	free(buf);
}

#include <sys/time.h>
#include <stdio.h>

/**
 * write single message to syslog
 *
 * @param priority syslog priority
 * @param s message to write
 * @see log_writen
 */
void
log_write(int priority, const char *s)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	char timebuf[64];
	ssize_t l = snprintf(timebuf, sizeof(timebuf) - 1, "%lu.%09lu\t", tv.tv_sec, tv.tv_usec);
	timebuf[l] = '\0';

#ifdef USESYSLOG
	syslog(priority, "%s", s);
#else
	(void)priority;
#endif
#ifndef NOSTDERR
	write(2, timebuf, l);
	write(2, s, strlen(s));
	write(2, "\n", 1);
#elif !defined(USESYSLOG) && defined(REALLY_NO_LOGGING)
	(void) s;
#endif
}
