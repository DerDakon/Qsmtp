/** \file control.c
 \brief function to load data from configuration files
 */
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
#include "mmap.h"

/**
 * load a text file into a buffer using locked IO
 *
 * @param fd file descriptor of the file to load
 * @param buf the contents of the file will go here, memory will be malloced
 * @param striptab 2: strip trailing whitespace
 *            1: compact {'\\0'}* to a single '\\0'
 *            0: do nothing but load the file into the buffer
 *
 * @return length of buffer on success, -1 on error (errno is set)
 *
 * if the file is empty (size 0 or only comments and blank lines) 0
 * is returned and buf is set to NULL
 *
 * \warning if lloadfilefd can't get a lock on the input file (e.g. currently opened for
 *          writing by another process) the file is treated as non existent
 */
size_t
lloadfilefd(int fd, char **buf, const int striptab)
{
	char *inbuf;
	size_t oldlen, j;
	int i;
	struct stat st;

	if (fd < 0) {
		if (errno == ENOENT) {
			*buf = NULL;
			return 0;
		} else
			return -1;
	}
	while (flock(fd, LOCK_SH)) {
		if (errno != EINTR) {
			log_write(LOG_WARNING, "cannot lock input file");
			errno = ENOLCK;	/* not the right error code, but good enough */
			return -1;
		}
	}
	if ( (i = fstat(fd, &st)) )
		return -1;
	if (!st.st_size) {
		*buf = NULL;
		while ( (i = close(fd)) && (errno == EINTR));
		return i;
	}
	oldlen = st.st_size + 1;
	inbuf = malloc(oldlen);
	if (!inbuf)
		return -1;
	j = 0;
	while (j < oldlen - 1) {
		if ( ((i = read(fd, inbuf + j, oldlen - 1 - j)) == -1) && (errno != EINTR) ) {
			int e = errno;

			while (close(fd) && (errno == EINTR));
			errno = e;
			return -1;
		}
		j += i;
	}
	while ( (i = close(fd)) ) {
		if (errno != EINTR)
			return -1;
	}
	inbuf[--oldlen] = '\0'; /* if file has no newline at the end */
	if (!striptab) {
		*buf = inbuf;
		return oldlen;
	}

	j = 0;
	while (j < oldlen) {
		if ((inbuf[j] == '#') && (!j || (inbuf[j - 1] != '\\'))) {
			/* this line contains a comment: strip it */
			while ( (inbuf[j] != '\0') && (inbuf[j] != '\n') )
				inbuf[j++] = '\0';
		} else if ((striptab  & 2) && ((inbuf[j] == ' ') || (inbuf[j] == '\t') )) {
			/* if there is a space or tab from here to the end of the line
			 * should not be anything else */
			do {
				inbuf[j++] = '\0';
			} while ((inbuf[j] == ' ') || (inbuf[j] == '\t'));
			if ((inbuf[j] != '\0') || (inbuf[j] != '\n')) {
				errno = EINVAL;
				return -1;
			}
		} else if (inbuf[j] == '\n') {
			inbuf[j++] = '\0';
		} else
			j++;
		/* maybe checking for \r and friends? */
	}

	if (striptab & 1) {
		size_t k;
		/* compact the buffer */
		j = k = 0;
		while ((j < oldlen) && !inbuf[j])
			j++;
		while (j < oldlen) {
			while (inbuf[j])
				inbuf[k++] = inbuf[j++];
			inbuf[k++] = '\0';
			while ((j < oldlen) && !inbuf[j])
				j++;
		}
		if (!k) {
			free(inbuf);
			*buf = NULL;
			return 0;
		}
		/* free the now useless memory at the end */
		*buf = realloc(inbuf, k);
		if (!*buf) {
			free(inbuf);
			j = -1;
		} else
			j = k;
	} else {
		for (j = 0; j < oldlen; j++) {
			if (inbuf[j]) {
				*buf = inbuf;
				return oldlen;
			}
		}
		free(inbuf);
		*buf = NULL;
		j = 0;
	}
	return j;
}

/**
 * read a control file containing a single integer
 *
 * @param fd file descriptor to read from (will be closed)
 * @param result value will be stored here
 * @param def default value if file does not exist
 * @return 0 on success, -1 on error. Parse errors in the file will set errno to EINVAL
 */
int
loadintfd(int fd, unsigned long *result, const unsigned long def)
{
	char *tmpbuf, *l;
	size_t i;

	if ( (i = lloadfilefd(fd, &tmpbuf, 2)) == (size_t) -1)
		return -1;

	if (!i) {
		*result = def;
		return 0;
	}

	*result = strtoul(tmpbuf, &l, 10);
	if (*l) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

/**
 * read a configuration file that only may contain one line
 *
 * @param filename don't know what this can ever mean ;)
 * @param buf the buffer where the contents of the file will go, memory will be malloced
 * @param optional if set to 0 write an error message to syslog if the file does not exist
 * @return length of the string, -1 on error
 */
size_t
loadoneliner(const char *filename, char **buf, int optional)
{
	size_t j;

	if ( (j = lloadfilefd(open(filename, O_RDONLY), buf, 3)) == (size_t) -1)
		return j;

	if (!*buf) {
		if (!optional) {
			const char *logmsg[] = {filename, " not found", NULL};

			log_writen(LOG_ERR, logmsg);
		}
		errno = ENOENT;
		return -1;
	}
	if (strlen(*buf) + 1 != j) {
		const char *logmsg[] = {"more than one line in ", filename, NULL};

		log_writen(LOG_ERR, logmsg);
		errno = EINVAL;
		return -1;
	}
	return j - 1;
}

/**
 * read a list from config file and validate entries
 *
 * @param fd file descriptor to read from (is closed on exit!)
 * @param buf the buffer where the data should be stored (memory will be malloced)
 * @param bufa array to be build from buf (memory will be malloced)
 * @param cf function to check if an entry is valid or NULL if not to
 * @return 0 on success, -1 on error
 *
 * if the file does not exist or has no content *buf and *bufa will be set to NULL
 */
int
loadlistfd(int fd, char **buf, char ***bufa, checkfunc cf)
{
	size_t i, j, k;

	if ( (j = lloadfilefd(fd, buf, 3)) == (size_t) -1)
		return -1;

	if (!j) {
		*bufa = NULL;
		return 0;
	}
	/* count the lines in buf */
	i = j - 1;
	k = j = 0;
	while (k < i) {
		if (!cf || !cf(*buf + k))
			j++;
		else {
			const char *s[] = {"input file contains invalid entry '", *buf + k, "'", NULL};

			log_writen(LOG_WARNING, s);
			/* mark this entry as invalid */
			(*buf)[k++] = '\0';
		}
		k += strlen(*buf + k) + 1;
	}
	if (!j) {
		/* only invalid entries in file */
		free(*buf);
		*bufa = NULL;
		*buf = NULL;
		return 0;
	}
	*bufa = malloc((j + 1) * sizeof(char*));
	if (!*bufa) {
		free(*buf);
		return -1;
	}
	i = k = 0;
	/* store references to the beginning of each valid entry */
	while (i < j) {
		while (!(*buf)[k]) {
			k += strlen(*buf + k + 1) + 2;
		}
		(*bufa)[i++] = *buf + k;
		k += strlen(*buf + k) + 1;
	}
	(*bufa)[j] = NULL;
	return 0;
}

/**
 * mmap a file and search a domain entry in it
 *
 * @param fd file descriptor
 * @param domain domain name to find
 * @param cl close fd or not
 * @return 1 on match, 0 if none, -1 on error
 *
 * trainling spaces and tabs in a line are ignored, lines beginning with '#' are ignored, CR in file will cause trouble
 */
int
finddomainfd(int fd, const char *domain, const int cl)
{
	char *map;
	int rc = 0, i;
	off_t len;

	if (fd < 0) {
		return (errno == ENOENT) ? 0 : fd;
	}

	while (flock(fd, LOCK_SH)) {
		if (errno != EINTR) {
			log_write(LOG_WARNING, "cannot lock input file");
			errno = ENOLCK;	/* not the right error code, but good enough */
			return -1;
		}
	}

	map = mmap_fd(fd, &len);

	if (map == NULL) {
		int e = errno;

		while (close(fd) && (errno == EINTR));
		errno = e;
		return -1;
	}

	rc = finddomainmm(map, len, domain);

	munmap(map, len);
	if (cl) {
		while ((i = close(fd))) {
			if (errno != EINTR) {
				break;
			}
		}
	} else {
		while ( (i = flock(fd, LOCK_UN)) ) {
			if (errno != EINTR) {
				log_write(LOG_WARNING, "cannot unlock input file");
				errno = ENOLCK;	/* not the right error code, but good enough */
				return -1;
			}
		}
	}
	return i ? i : rc;
}

/**
 * search a domain entry in a mmaped memory area
 *
 * @param map memory region where file ist mmapped to
 * @param size size of mmapped area
 * @param domain domain name to find
 * @return 1 on match, 0 if none, -1 on error
 *
 * trainling spaces and tabs in a line are ignored, lines beginning with '#' are ignored, CR in file will cause trouble
 */
int
finddomainmm(const char *map, const off_t size, const char *domain)
{
	const char *cur;
	size_t dl = strlen(domain);
	off_t pos = 0;

	if (!map)
		return 0;

	cur = map;
	do {
		char *cure = memchr(cur, '\n', size - pos);
		size_t len;

		if (*cur != '#') {
			if (cure) {
				len = cure - cur;
			} else {
				/* last entry, missing newline at end of file */
				len = size - pos - 1;
			}
			while (((*(cur + len) == ' ') || (*(cur + len) == '\t')) && len)
				len--;
			if (len) {
				if (*cur == '.') {
					if (dl > len) {
						if (!strncasecmp(domain + dl - len, cur, len)) {
							return 1;
						}
					}
				} else {
					if ((dl == len) && !strncasecmp(domain, cur, len)) {
						return 1;
					}
				}
			}
		}
		cur = cure;
		if (cure) {
			while (*cur == '\n') {
				cur++;
			}
			pos = cur - map;
		}
	} while (cur);

	return 0;
}
