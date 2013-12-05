/** \file vpop.c
 \brief function to get domain directory of vpopmail virtual domain
 */
#include <sys/mman.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "vpop.h"
#include "sstring.h"
#include "cdb.h"

/*
 * The function vget_dir is a modified copy of vget_assign from vpopmail. It gets the domain directory out of
 * the /var/qmail/users/cdb file. All the unneeded code (buffering, rewrite the domain name, uid, gid) is ripped out,
 * the ugly snprintf stuff is gone, the result of malloc() is checked and the code is much prettier (at least IMHO,
 * but that's the only one that counts here *g*).
 */

/**
 * Query the users/cdb file for information about this domain
 *
 * @param domain the domain to query
 * @param domaindir if not NULL the directory of this domain is stored here
 * @param realdomain if not NULL name of the real domain is stored here
 * @returns negative error code or flag if domain was found
 * @retval 0 domain is not in database
 * @retval 1 domain was found
 *
 * Function will return 1 on success, memory for domaindir will be malloced.
 * The directory name will always end with a single '/'. If the domain does not exist 0 is returned, -1 on error;
 */
int vget_dir(const char *domain, string *domaindir, char **realdomain)
{
	int fd;
	char *cdb_key;
	size_t cdbkeylen;
	const char *cdb_buf;
	char *cdb_mmap = NULL;
	int err;
	struct stat st;
	size_t len;

	cdbkeylen = strlen(domain) + 2;
	cdb_key = malloc(cdbkeylen + 1);
	if (!cdb_key)
		return -ENOMEM;
	cdb_key[0] = '!';
	memcpy(cdb_key + 1, domain, cdbkeylen - 2);
	cdb_key[cdbkeylen - 1] = '-';
	cdb_key[cdbkeylen] = '\0';

	/* try to open the cdb file */
	fd = open("users/cdb", O_RDONLY);
	if (fd < 0) {
		err = -errno;
		free(cdb_key);
		return err;
	}

	if (fstat(fd, &st) < 0) {
		err = -errno;
		while ((close(fd) < 0) && (errno == EINTR));
		free(cdb_key);
		return err;
	}
	if (!st.st_size) {
		err = 0;
		while (close(fd) < 0) {
			if (errno != EINTR) {
				err = -errno;
				break;
			}
		}
		free(cdb_key);
		return err;
	}

	/* search the cdb file for our requested domain */
	cdb_buf = cdb_seekmm(fd, cdb_key, cdbkeylen, &cdb_mmap, &st);
	if (cdb_buf == NULL) {
		free(cdb_key);
		return errno ? -errno : 0;
	}

	/* format of cdb_buf is :
	 * realdomain\0uid\0gid\0path\0
	 */
	len = strlen(cdb_buf);
	if (realdomain) {
		*realdomain = malloc(len + 1);
		if (!*realdomain) {
			munmap(cdb_mmap, st.st_size);
			free(cdb_key);
			return -ENOMEM;
		}
		memcpy(*realdomain, cdb_buf, len + 1);
	}
	cdb_buf += len + 1;	/* advance pointer past the realdomain */
	while( *cdb_buf++ != '\0' );	/* skip over the uid */
	while( *cdb_buf++ != '\0' );	/* skip over the gid */

	/* get the domain directory */
	if (domaindir) {
		int i;

		len = strlen(cdb_buf);
		while (*(cdb_buf + len - 1) == '/')
			--len;
		i = newstr(domaindir, len + 2);
		if (i != 0) {
			munmap(cdb_mmap, st.st_size);
			free(cdb_key);
			if (realdomain != NULL)
				free(realdomain);
			return -ENOMEM;
		}

		memcpy(domaindir->s, cdb_buf, len);
		domaindir->s[len] = '/';
		domaindir->s[--domaindir->len] = '\0';
	}

	err = errno;
	munmap(cdb_mmap, st.st_size);
	free(cdb_key);
	errno = err;
	return 1;
}
