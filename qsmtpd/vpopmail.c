/** \file vpopmail.c
 \brief function to get domain directory of vpopmail virtual domain
 */
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "vpopmail.h"
#include "sstring.h"
#include "cdb.h"

/*
 * The function vget_assign is a modified copy of the one from vpopmail. It gets the domain directory out of
 * the /var/qmail/users/cdb file. All the unneeded code (buffering, rewrite the domain name, uid, gid) is ripped out,
 * the ugly snprintf stuff is gone, the result of malloc() is checked and the code is much prettier (at least IMHO,
 * but that's the only one that counts here *g*).
 */

/*
 * Given the domain name:
 *
 *   get dir  users/cdb file (if they are not passed as NULL)
 *
 * Function will return 1 on success, memory for domaindir will be malloced.
 * The directory name will always end with a single '/'. If the domain does not exist 0 is returned, -1 on error;
 */
int vget_assign(const char *domain, string *domaindir)
{
	int fd;
	int i;

	char *cdb_key;
	unsigned int cdbkeylen;
	char *cdb_buf;
	char *cdb_mmap = NULL;
	int err;
	struct stat st;

	cdbkeylen = strlen(domain) + 2;
	cdb_key = malloc(cdbkeylen + 1);
	if (!cdb_key)
		return -1;
	cdb_key[0] = '!';
	memcpy(cdb_key + 1, domain, cdbkeylen - 2);
	cdb_key[cdbkeylen - 1] = '-';
	cdb_key[cdbkeylen] = '\0';

	/* try to open the cdb file */
	fd = open("users/cdb", O_RDONLY);
	if (fd < 0)
		return fd;

	if ( (err = fstat(fd, &st)) )
		return err;
	if (!st.st_size) {
		while ((err = close(fd)) && (errno == EINTR));
		return err;
	}

	/* search the cdb file for our requested domain */
	if ( !(cdb_buf = cdb_seekmm(fd, cdb_key, cdbkeylen, &cdb_mmap, &st)) ) {
		unsigned int len;

		/* format of cdb_buf is :
		 * realdomain\0uid\0gid\0path\0
		 */
		while( *cdb_buf++ != '\0' );	/* advance pointer past the realdomain */
		while( *cdb_buf++ != '\0' );	/* skip over the uid */
		while( *cdb_buf++ != '\0' );	/* skip over the gid */

		/* get the domain directory */
		len = strlen(cdb_buf);
		while (*(cdb_buf + len - 1) == '/')
			--len;
		i = newstr(domaindir, len + 2);
		if (!i) {
			memcpy(domaindir->s, cdb_buf, len);
			domaindir->s[len] = '/';
			domaindir->s[--domaindir->len] = '\0';

			i++;
		}
	} else {
		return errno ? -1 : 0;
	}
	err = errno;
	munmap(cdb_mmap, st.st_size);
	while (close(fd) && (errno == EINTR));
	free(cdb_key);
	errno = err;
	return i;
}
