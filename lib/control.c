#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include "log.h"
#include "dns.h"
#include "control.h"

/**
 * lloadfilefd - load a text file into a buffer using locked IO
 *
 * fd: file descriptor of the file to load
 * buf: the contents of the file will go here, memory will be malloced
 * striptab: 2: strip anything after the first space or tab in a line,
 *           1: compact {'\0'}* to a single '\0'
 *           0: do nothing but load the file into the buffer
 *
 * returns: length of buffer on success, -1 on error (errno is set)
 *
 * if the file is empty (size 0 or only comments and blank lines) ENOENT is returned
 */
int
lloadfilefd(int fd, char **buf, const int striptab)
{
	char *inbuf;
	int oldlen, j, i;
	struct stat st;

	if (fd < 0) {
		if (errno == ENOENT) {
			*buf = NULL;
			return 0;
		} else
			return -1;
	}
	while (flock(fd,LOCK_SH)) {
		if (errno != EINTR) {
			log_write(LOG_WARNING, "cannot lock input file");
			errno = ENOLCK;	/* not the right error code, but good enough */
			return -1;
		}
	}
	if ( (i = fstat(fd, &st)) )
		return i;
	oldlen = st.st_size + 1;
	if (!oldlen) {
		*buf = NULL;
		while ( (i = close(fd)) && (errno != EINTR));
		return i ? i : 0;
	}
	inbuf = malloc(oldlen);
	if (!inbuf)
		return -1;
	if ( (i = read(fd, inbuf, oldlen)) < 0 )
		return i;
	while ( (i = close(fd)) ) {
		if (errno != EINTR)
			return i;
	}
	inbuf[--oldlen] = '\0'; /* if file has no newline at the end */
	if (!striptab) {
		*buf = inbuf;
		return oldlen;
	}

	i = 0;
	while (i < oldlen) {
		if (inbuf[i] == '#') {
			/* this line contains a comment: strip it */
			while ( (inbuf[i] != '0') && (inbuf[i] != '\n') )
				inbuf[i++] = '\0';
		} else if ((striptab  == 2) && ((inbuf[i] == ' ') || (inbuf[i] == '\t') )) {
			/* if there is a space or tab from here to the end of the line
			 * should not be anything else */
			do {
				inbuf[i++] = '\0';
			} while ((inbuf[i] == ' ') || (inbuf[i] == '\t'));
			if ((inbuf[i] != '\0') || (inbuf[i] != '\n')) {
				errno = EINVAL;
				return -1;
			}
		} else if (inbuf[i] == '\n') {
			inbuf[i++] = '\0';
		} else
			i++;
		/* maybe checking for \r and friends? */
	}
	/* compact the buffer */
	j = i = 0;
	while (i < oldlen) {
		while (inbuf[i])
			inbuf[j++] = inbuf[i++];
		inbuf[j++] = '\0';
		while ((i < oldlen) && !inbuf[i])
			i++;
	}
	if (j == 1) {
		free(*buf);
		*buf = NULL;
		return 0;
	}
	/* free the now useless memory at the end */
	*buf = realloc(inbuf, j);
	if (!*buf) {
		free(inbuf);
		j = -1;
	}
	return j;
}

int
loadintfd(int fd, unsigned long *result, const unsigned long def)
{
	char *tmpbuf;
	int i;

	if ( ( i = lloadfilefd(fd, &tmpbuf, 2)) < 0)
		return i;

	if (tmpbuf) {
		char *l;
		*result = strtoul(tmpbuf, &l, 10);
		if (*l) {
			/* skip trailing spaces and tabs */
			while  ( (*l == ' ') || (*l == '\t') || (*l == '\n') )
				*l++;
			if (*l) {
				errno = EINVAL;
				return -1;
			}
		}
	} else
		*result = def;
	return 0;
}

/**
 * loadoneliner - read a configuration file that only may contain one line
 *
 * filename: don't know what this can ever mean ;)
 * buf: the buffer where the contents of the file will go, memory will be malloced
 * optional: if set to 0 raise an error if the file does not exist
 *
 * returns: length of the string
 */
int
loadoneliner(const char *filename, char **buf, int optional)
{
	int j;

	if ( ( j = lloadfilefd(open(filename, O_RDONLY), buf, 3) ) < 0)
		return j;

	if (!*buf) {
		if (!optional) {
			const char *logmsg[] = {filename, " not found", NULL};

			log_writen(LOG_ERR, logmsg);
		}
		errno = ENOENT;
		return -1;
	}
	if (strlen(*buf) + 1 != (unsigned int) j) {
		const char *logmsg[] = {"more than one line in ", filename, NULL};

		log_writen(LOG_ERR, logmsg);
		errno = EINVAL;
		return -1;
	}
	return j - 1;
}

/**
 * loadlistfd - read a list from config file and validate entries
 *
 * fd: file descriptor to read from (is closed on exit!)
 * buf: the buffer where the data should be stored (memory will be malloced)
 * bufa: array to be build from buf (memory will be malloced)
 * cf: function to check if an entry is valid or NULL if not to
 * f: second parameter of cf
 */
int
loadlistfd(int fd, char **buf, char ***bufa, checkfunc cf, int f)
{
	int i, j, k;

	if ( (j = lloadfilefd(fd, buf, 3)) < 0)
		return j;

	/* count the lines in buf */
	i = j - 1;
	k = j = 0;
	while (k < i) {
		k += strlen(*buf + k) + 1;
		j++;
	}
	/* store references to the beginning of each host in the array */
	*bufa = malloc((j + 1) * sizeof(char*));
	if (!*bufa) {
		free(*buf);
		return -1;
	}
	k = j = 0;
	while (k < i) {
		(*bufa)[j] = *buf + k;
		if (!cf || !cf(*buf + k,f))
			j++;
		else {
			const char *s[] = {"input file contains invalid entry '",*buf + k, "'", NULL};

			log_writen(LOG_WARNING, s);
		}
		k += strlen(*buf + k) + 1;
	}
	(*bufa)[j] = NULL;
	return 0;
}

/**
 * finddomainmm - mmap a file and search a domain entry in it
 *
 * @fd: file descriptor
 * @domain: domain name to find
 *
 * returns: 1 on match, 0 if none, -1 on error
 *
 * trainling spaces and tabs in a line are ignored, lines beginning with '#' are ignored, '\r' in file will cause trouble
 */
int
finddomainmm(int fd, const char *domain)
{
	struct stat st;
	char *map, *cur;
	int rc = 0, i;
	unsigned int dl = strlen(domain);

	if (fd < 0) {
		return (errno == ENOENT) ? 0 : fd;
	}

	while (flock(fd,LOCK_SH)) {
		if (errno != EINTR) {
			log_write(LOG_WARNING, "cannot lock input file");
			errno = ENOLCK;	/* not the right error code, but good enough */
			return -1;
		}
	}
	if ( (rc = fstat(fd, &st)) )
		return rc;
	if (!st.st_size) {
		while ( (rc = close(fd)) ) {
			if (errno != EINTR)
				return rc;
		}
		return 0;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		int e = errno;

		while (close(fd)) {
			if (errno != EINTR)
				break;
		}
		errno = e;
		return -1;
	}

	cur = map;
	do {
		char *cure = strchr(cur, '\n');
		unsigned int len;

		if (cure) {
			len = cure - cur;
		} else {
			len = map + st.st_size - cur;
		}
		while (((*(cur + len) == ' ') || (*(cur + len) == '\t')) && len)
			len--;
		if ((*cur != '#') && len) {
			if (*cur == '.') {
				if (dl > len) {
					if (!strncasecmp(domain + dl - len, cur, len)) {
						rc = 1;
						break;
					}
				}
			} else {
				if ((dl == len) && !strncasecmp(domain, cur, len)) {
					rc = 1;
					break;
				}
			}
		}
		cur = cure;
		if (cure) {
			while (*cur == '\n') {
				cur++;
			}
		}
	} while (cur);

	munmap(map, st.st_size);
	while ((i = close(fd))) {
		if (errno != EINTR) {
			break;
		}
	}
	return i ? i : rc;
}
