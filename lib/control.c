/** \file control.c
 \brief functions to load data from configuration files
 */

#include <control.h>

#include <fmt.h>
#include <log.h>
#include <mmap.h>
#include <qdns.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

int controldir_fd = -1;	/**< descriptor of the control directory */

/**
 * @brief compact a given buffer
 *
 * @param buf output parameter
 * @param inbuf the buffer to compact
 * @param oldlen the current length of inbuf
 * @return the length of the new buffer
 * @retval 0 no valid entries were found in inbuf, inbuf was freed
 */
static size_t
compact_buffer(char **buf, char *inbuf, size_t oldlen)
{
	size_t j = 0, k = 0;

	/* skip over any leading 0-bytes, i.e. deleted entries */
	while ((j < oldlen) && !inbuf[j])
		j++;

	while (j < oldlen) {
		const size_t jlen = strnlen(inbuf + j, oldlen - j);

		/* only copy if not already at the right place */
		if (j != k)
			memmove(inbuf + k, inbuf + j, jlen);

		j += jlen + 1; /* skip over the trailing 0-byte */
		k += jlen;

		inbuf[k++] = '\0';

		while ((j < oldlen) && !inbuf[j])
			j++;
	}
	/* file consists only of comments and whitespace */
	if (!k) {
		free(inbuf);
		return 0;
	}

	/* free the now useless memory at the end (if any) */
	j = k;
	if (k != oldlen + 1) {
		*buf = realloc(inbuf, k);
		if (*buf == NULL)
			/* Can't shrink? Well, then the long buffer */
			*buf = inbuf;
	} else {
		*buf = inbuf;
	}

	return j;
}

/**
 * load a text file into a buffer using locked IO
 *
 * @param fd file descriptor of the file to load
 * @param buf the contents of the file will go here, memory will be malloced
 * @param striptab 2: strip trailing whitespace
 *            1: compact {'\\0'}* to a single '\\0'
 *            0: do nothing but load the file into the buffer
 *
 * @return length of buffer
 * @retval -1 on error (errno is set)
 *
 * if the file is empty (size 0 or only comments and blank lines) 0
 * is returned and buf is set to NULL
 *
 * \warning if lloadfilefd can't get a lock on the input file (e.g. currently opened for
 *          writing by another process) the file is treated as non existent
 *
 * The input file will be closed before this function returns.
 *
 * striptab == 2 means: the only whitespace in a non-comment line may be immediately
 * before the line break, in any amount.
 *
 * buf is always in a sane state when this function returns: either it is NULL
 * or a valid buffer, in the latter case the return value will be >0.
 */
size_t
lloadfilefd(int fd, char **buf, const int striptab)
{
	char *inbuf;
	size_t oldlen, j;
	struct stat st;

	*buf = NULL;
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		else
			return -1;
	}
	if (flock(fd, LOCK_SH | LOCK_NB) != 0) {
		char errcode[ULSTRLEN];
		const char *logmsg[] = { "cannot lock input file, error code ",
				errcode, NULL };

		ultostr(errno, errcode);
		log_writen(LOG_WARNING, logmsg);
		close(fd);
		errno = ENOLCK;	/* not the right error code, but good enough */
		return -1;
	}
	if (fstat(fd, &st) != 0) {
		int err = errno;
		close(fd);
		errno = err;
		return -1;
	}
	if (!st.st_size) {
		return close(fd);
	}
	oldlen = st.st_size;
	inbuf = malloc(oldlen + 1);
	if (!inbuf) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}
	j = 0;
	while (j < oldlen) {
		const ssize_t k = read(fd, inbuf + j, oldlen - j);
		if (k == -1) {
			int e = errno;

			close(fd);
			free(inbuf);
			errno = e;
			return -1;
		}
		if (k > 0)
			j += k;
	}
	close(fd);
	inbuf[oldlen] = '\0'; /* if file has no newline at the end */
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
		} else if ((striptab & 2) && ((inbuf[j] == ' ') || (inbuf[j] == '\t') )) {
			/* if there is a space or tab from here to the end of the line
			 * should not be anything else */
			do {
				inbuf[j++] = '\0';
			} while ((inbuf[j] == ' ') || (inbuf[j] == '\t'));
			if ((inbuf[j] != '\0') && (inbuf[j] != '\n')) {
				free(inbuf);
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
		j = compact_buffer(buf, inbuf, oldlen);
	} else {
		for (j = 0; j < oldlen; j++) {
			if (inbuf[j]) {
				*buf = inbuf;
				return oldlen;
			}
		}
		free(inbuf);
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
 * @retval 0 on success
 * @retval -1 on error, parse errors in the file will set errno to EINVAL
 */
int
loadintfd(int fd, unsigned long *result, const unsigned long def)
{
	char *tmpbuf, *l;
	const size_t i = lloadfilefd(fd, &tmpbuf, 2);

	if (i == (size_t) -1)
		return -1;

	if (!i) {
		*result = def;
		return 0;
	}

	*result = strtoul(tmpbuf, &l, 10);
	if (*l) {
		errno = EINVAL;
		free(tmpbuf);
		return -1;
	}

	free(tmpbuf);

	return 0;
}

/**
 * @brief read a configuration file that only may contain one line
 * @param base descriptor of a file descriptor serving as base for relative paths
 * @param filename don't know what this can ever mean ;)
 * @param buf the buffer where the contents of the file will go, memory will be malloced
 * @param optional if set to 0 write an error message to syslog if the file does not exist
 * @return length of the string
 * @retval -1 on error
 */
size_t
loadoneliner(int base, const char *filename, char **buf, const int optional)
{
	size_t j;
	int fd;

	fd = openat(base, filename, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		j = (size_t)-1;
		*buf = NULL;
	} else {
		j = loadonelinerfd(fd, buf);
	}

	if (j == (size_t)-1) {
		if ((errno == ENOENT) && !optional) {
			const char *logmsg[] = {filename, " not found", NULL};

			log_writen(LOG_ERR, logmsg);
			errno = ENOENT;
		} else if (errno == EINVAL) {
			const char *logmsg[] = {"more than one line in ", filename, NULL};

			log_writen(LOG_ERR, logmsg);
			errno = EINVAL;
		}
	}
	return j;
}

/**
* read a configuration file that only may contain one line
*
* @param fd opened file descriptor
* @param buf the buffer where the contents of the file will go, memory will be malloced
* @return length of the string
* @retval -1 on error
*
* fd will be closed.
*/
size_t
loadonelinerfd(int fd, char **buf)
{
	const size_t j = lloadfilefd(fd, buf, 1);

	if (j == (size_t) -1)
		return j;

	if (!*buf) {
		errno = ENOENT;
		return (size_t)-1;
	}

	if (strlen(*buf) + 1 != j) {
		free(*buf);
		*buf = NULL;

		errno = EINVAL;
		return (size_t)-1;
	}

	return j - 1;
}

/**
 * @brief create a combined data and pointer array
 *
 * @param entries how many entries should be in the pointer array (not counting the terminating NULL entry)
 * @param datalen length needed for the data, 1 byte per entry is added for the terminating '\0' characters
 * @param oldbuf if a previous buffer should be realloc()ed, may be NULL
 * @param oldlen length of oldbuf, must be 0 if oldbuf is NULL
 * @returns new buffer or NULL on error
 *
 * If oldbuf is given the contents of the old buffer are moved to the beginning of the data
 * section of the new memory area.
 *
 * If oldbuf is given, but reallocation fails (i.e. NULL is returned), then oldbuf is not freed.
 */
char **
data_array(unsigned int entries, size_t datalen, void *oldbuf, size_t oldlen)
{
	size_t psize = (entries + 1) * sizeof(char **);	/* size of pointer section */
	size_t dsize = entries + datalen;
	char **ret = realloc(oldbuf, psize + dsize);

	assert(dsize >= oldlen);
	assert(!((oldbuf == NULL) && (oldlen != 0)));

	if (ret == NULL)
		return ret;

	if (oldlen != 0) {
		/* move the data beyond the pointer array */
		void *buf = (void *)(((uintptr_t)ret) + psize);
		memmove(buf, ret, oldlen);
	}

	ret[entries] = NULL;

	return ret;
}

/**
 * read a list from config file and validate entries
 *
 * @param fd file descriptor to read from (is closed on exit!)
 * @param bufa array to be build from buf (memory will be malloced)
 * @param cf function to check if an entry is valid or NULL if not to
 * @retval 0 on success
 * @retval -1 on error
 *
 * If the file does not exist or has no content *bufa will be set to NULL
 * and 0 is returned.
 */
int
loadlistfd(int fd, char ***bufa, checkfunc cf)
{
	size_t i, k, j;
	char *buf;
	const size_t datalen = lloadfilefd(fd, &buf, 3);

	if (datalen == (size_t) -1)
		return -1;

	if (datalen == 0) {
		*bufa = NULL;
		return 0;
	}
	/* count the lines in buf */
	i = datalen - 1;
	k = j = 0;
	while (k < i) {
		if (!cf || !cf(buf + k))
			j++;
		else {
			const char *s[] = {"input file contains invalid entry '", buf + k, "'", NULL};

			log_writen(LOG_WARNING, s);
			/* mark this entry as invalid */
			buf[k++] = '\0';
		}
		k += strlen(buf + k) + 1;
	}
	if (!j) {
		/* only invalid entries in file */
		free(buf);
		*bufa = NULL;
		return 0;
	}

	*bufa = data_array(j, datalen, buf, datalen);
	if (!*bufa) {
		free(buf);
		return -1;
	}
	buf = (char*)(*bufa + (j + 1));

	i = k = 0;
	/* store references to the beginning of each valid entry */
	while (i < j) {
		while (!buf[k]) {
			k += strlen(buf + k + 1) + 2;
		}
		(*bufa)[i++] = buf + k;
		k += strlen(buf + k) + 1;
	}
	return 0;
}

/**
 * mmap a file and search a domain entry in it
 *
 * @param fd file descriptor
 * @param domain domain name to find
 * @param cl close fd or not
 * @retval 1 on match
 * @retval 0 if none
 * @retval -1 on error
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

	while (flock(fd, LOCK_SH | LOCK_NB)) {
		close(fd);
		log_write(LOG_WARNING, "cannot lock input file");
		errno = ENOLCK;	/* not the right error code, but good enough */
		return -1;
	}

	map = mmap_fd(fd, &len);

	if (map == NULL) {
		int e = errno;

		close(fd);
		errno = e;
		return -1;
	}

	rc = finddomain(map, len, domain);

	munmap(map, len);
	if (cl) {
		i = close(fd);
	} else {
		i = flock(fd, LOCK_UN);
		if (i != 0) {
			log_write(LOG_WARNING, "cannot unlock input file");
			errno = ENOLCK;	/* not the right error code, but good enough */
			return -1;
		}
	}
	return i ? i : rc;
}

/**
 * @brief search a domain entry in a given buffer
 *
 * @param buf containing the domain list
 * @param size size of buffer
 * @param domain domain name to find
 * @retval 1 on match
 * @retval 0 if none
 *
 * trailing spaces and tabs in a line are ignored, lines beginning with '#' are ignored, CR in file will cause trouble
 */
int
finddomain(const char *buf, const off_t size, const char *domain)
{
	const char *cur;
	size_t dl = strlen(domain);
	off_t pos = 0;

	if (!buf)
		return 0;

	cur = buf;
	do {
		char *cure = memchr(cur, '\n', size - pos);

		if (*cur != '#') {
			size_t len;
			if (cure) {
				len = cure - cur;
			} else {
				/* last entry, missing newline at end of file */
				len = size - pos;
			}
			while (len && ((*(cur + len - 1) == ' ') || (*(cur + len - 1) == '\t')))
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
			pos = cur - buf;
		}
	} while (cur);

	return 0;
}
