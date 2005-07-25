/** \file vpopmail.c
 \brief function to get domain directory of vpopmail virtual domain
 */
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "vpopmail.h"
#include "sstring.h"

/*
 * The function vget_assign is a modified copy of the one from vpopmail. It gets the domain directory out of
 * the /var/qmail/users/cdb file. All the unneeded code (buffering, rewrite the domain name, uid, gid) is ripped out,
 * the ugly snprintf stuff is gone, the result of malloc() is checked and the code is much prettier (at least IMHO,
 * but that's the only one that counts here *g*).
 */

/* this is a bit ugly but better than including some vpopmail header files where the parameters are not listed */
extern int cdb_seek(int fd, char *key, unsigned int len, unsigned int *dlen);

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
	unsigned int dlen;
	int i;

	char *cdb_key;
	unsigned int cdbkeylen;

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

	/* search the cdb file for our requested domain */
	i = cdb_seek(fd, cdb_key, cdbkeylen, &dlen);

	if ( i == 1 ) {
		unsigned int len;
		char *cdb_buf;
		char *ptr;

		/* we found a matching record in the cdb file
		* so next create a storage buffer, and then read it in
		*/
		cdb_buf = malloc(dlen);
		if (!cdb_buf) {
			i = -1;
			goto out;
		}
		i = read(fd, cdb_buf, dlen);
		if (i < 0) {
			free(cdb_buf);
			goto out;
		}
	
		/* format of cdb_buf is :
		* realdomain.com\0uid\0gid\0path\0
		*/
	
		/* get the real domain */
		ptr = cdb_buf;			/* point to start of cdb_buf (ie realdomain) */
		
		while( *ptr != 0 ) ptr++;		/* advance pointer past the realdomain */
		ptr++;				/* skip over the null */
		
		while( *ptr != 0 ) ptr++;	/* skip over the uid */
		ptr++;				/* skip over the null */
		
		/* get the domain directory */
		while( *ptr != 0 ) ptr++;	/* skip over the gid */
		ptr++;				/* skip over the null */
		len = strlen(ptr);
		while (*(ptr + len - 1) == '/')
			--len;
		i = newstr(domaindir, len + 2);
		if (i) {
			i = -1;
			free(cdb_buf);
			goto out;
		}
		memcpy(domaindir->s, ptr, len);
		domaindir->s[len] = '/';
		domaindir->s[--domaindir->len] = '\0';
	
		free(cdb_buf);
		i++;
	}
out:
	while (close(fd) && (errno == EINTR));
	free(cdb_key);
	return i;
}
