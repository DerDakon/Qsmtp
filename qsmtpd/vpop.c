/** \file vpop.c
 \brief function to get domain directory of vpopmail virtual domain
 */
#include <qsmtpd/vpop.h>

#include <qsmtpd/addrparse.h>
#include <cdb.h>
#include <qsmtpd/qsmtpd.h>
#include <sstring.h>

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

char *vpopbounce;			/**< the bounce command in vpopmails .qmail-default */

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
 * The directory name will always end with a single '/' and be 0-terminated.
 * If the domain does not exist 0 is returned, -1 on error;
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

/* values for default

  (def & 1)		append "default"
  (def & 2)		append suff1
 */

static int
qmexists(const string *dirtempl, const char *suff1, const unsigned int len, const int def)
{
	char filetmp[PATH_MAX];
	int fd;
	unsigned int l = dirtempl->len;

	errno = ENOENT;
	if (l >= PATH_MAX)
		return -1;
	memcpy(filetmp, dirtempl->s, l);
	if (def & 2) {
		char *p;

		if (l + len >= PATH_MAX)
			return -1;
		memcpy(filetmp + l, suff1, len);

		while ( (p = strchr(filetmp + l, '.')) ) {
			*p = ':';
		}
		l += len;
		if (def & 1) {
			if (l + 1 >= PATH_MAX)
				return -1;
			*(filetmp + l) = '-';
			l++;
		}
	}
	if (def & 1) {
		if (l + 7 >= PATH_MAX)
			return -1;
		memcpy(filetmp + l, "default", 7);
		l += 7;
	}
	filetmp[l] = 0;

	/* these files should not be open long enough to reach a close, but
	 * make sure it is not accidentially leaked. */
	fd = open(filetmp, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		if ((errno == ENOMEM) || (errno == ENFILE) || (errno == EMFILE)) {
			errno = ENOMEM;
		} else if ((errno != ENOENT) && (errno != EACCES)) {
			err_control(filetmp);
		}
	}
	return fd;
}

/** check if the user identified by localpart and userconf->domainpath exists
 *
 * \param localpart localpart of mail address
 * \param ds path of domain and user
 *
 * \return \arg \c 0: user doesn't exist
 *         \arg \c 1: user exists
 *         \arg \c 2: mail would be catched by .qmail-default and .qmail-default != vpopbounce
 *         \arg \c 3: domain is not filtered (use for domains not local)
 *         \arg \c 4: mail would be catched by .qmail-foo-default (i.e. mailinglist)
 *         \arg \c -1: error, errno is set.
*/
int
user_exists(const string *localpart, struct userconf *ds)
{
	DIR *dirp;

	/* '/' is a valid character for localparts but we don't want it because
	 * it could be abused to check the existence of files */
	if (strchr(localpart->s, '/'))
		return 0;

	/* does directory (ds->domainpath.s)+'/'+localpart exist? */
	dirp = opendir(ds->userpath.s);
	if (dirp == NULL) {
		char filetmp[PATH_MAX];
		int e = errno;
		int fd;
		string dotqm;
		size_t i;

		/* userpath is already 0-terminated */
		memcpy(filetmp, ds->userpath.s, ds->userpath.len + 1);

		free(ds->userpath.s);
		STREMPTY(ds->userpath);
		if (e == EACCES) {
			/* Directory is not readable. Admins fault, we accept the mail. */
			free(ds->domainpath.s);
			STREMPTY(ds->domainpath);
			return 1;
		} else if (e != ENOENT) {
			if (!err_control(filetmp)) {
				errno = e;
			} else {
				errno = EDONE;
			}
			return -1;
		}
		/* does USERPATH/DOMAIN/.qmail-LOCALPART exist? */
		i = ds->domainpath.len;
		memcpy(filetmp, ds->domainpath.s, i);
		memcpy(filetmp + i, ".qmail-", 7);
		i += 7;
		filetmp[i] = '\0';
		if ( (fd = newstr(&dotqm, i + 1)) ) {
			return fd;
		}
		memcpy(dotqm.s, filetmp, dotqm.len--);
		fd = qmexists(&dotqm, localpart->s, localpart->len, 2);
		/* try .qmail-user-default instead */
		if (fd < 0) {
			if (errno == EACCES) {
				/* User exists */
				free(dotqm.s);
				return 1;
			} else if (errno == ENOMEM) {
				return fd;
			} else if (errno != ENOENT) {
				free(dotqm.s);
				return EDONE;
			} else {
				fd = qmexists(&dotqm, localpart->s, localpart->len, 3);
			}
		}

		if (fd < 0) {
			char *p;

			if (errno == EACCES) {
				/* User exists */
				free(dotqm.s);
				return 1;
			} else if (errno == ENOMEM) {
				return fd;
			} else if (errno != ENOENT) {
				free(dotqm.s);
				return EDONE;
			}
			/* if username contains '-' there may be
			 .qmail-partofusername-default */
			p = strchr(localpart->s, '-');
			while (p) {
				fd = qmexists(&dotqm, localpart->s, (p - localpart->s), 3);
				if (fd < 0) {
					if (errno == EACCES) {
						free(dotqm.s);
						return 1;
					} else if (errno == ENOMEM) {
						return fd;
					} else if (errno != ENOENT) {
						free(dotqm.s);
						errno = EDONE;
						return -1;
					}
				} else {
					free(dotqm.s);
					while (close(fd)) {
						if (errno != EINTR)
							return -1;
					}
					return 4;
				}
				p = strchr(p + 1, '-');
			}

			/* does USERPATH/DOMAIN/.qmail-default exist ? */
			fd = qmexists(&dotqm, NULL, 0, 1);
			free(dotqm.s);
			if (fd < 0) {
				/* no local user with that address */
				if (errno == EACCES) {
					return 1;
				} else if (errno == ENOENT) {
					return 0;
				} else if (errno == ENOMEM) {
					return fd;
				} else {
					return EDONE;
				}
			} else if (vpopbounce) {
				char buff[2*strlen(vpopbounce)+1];
				ssize_t r;
				int err = 0;

				r = read(fd, buff, sizeof(buff) - 1);
				if (r == -1) {
					if (!err_control(filetmp))
						err = EDONE;
					else
						err = errno;
				}
				while (close(fd)) {
					if (errno != EINTR) {
						if (err == 0)
							err = errno;
						break;
					}
				}
				if (err != 0) {
					errno = err;
					return -1;
				}

				buff[r] = 0;

				/* mail would be bounced or catched by .qmail-default */
				return strcmp(buff, vpopbounce) ? 2 : 0;
			} else {
				/* we can't tell if this is a bounce .qmail-default -> accept the mail */
				return 2;
			}
		} else {
			free(dotqm.s);
			while (close(fd)) {
				if (errno != EINTR)
					return -1;
			}
		}
	} else {
		closedir(dirp);
	}
	return 1;
}
