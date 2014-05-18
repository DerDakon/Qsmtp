/** \file vpop.c
 * \brief function to get domain directory of vpopmail virtual domain
 */
#include <qsmtpd/vpop.h>

#include <control.h>
#include <qsmtpd/addrparse.h>
#include <cdb.h>
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>
#include <qsmtpd/userfilters.h>
#include <sstring.h>

#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static char *vpopbounce;			/**< the bounce command in vpopmails .qmail-default */

/*
 * The function vget_dir is a modified copy of vget_assign from vpopmail. It gets the domain directory out of
 * the /var/qmail/users/cdb file. All the unneeded code (buffering, rewrite the domain name, uid, gid) is ripped out,
 * the ugly snprintf stuff is gone, the result of malloc() is checked and the code is much prettier (at least IMHO,
 * but that's the only one that counts here *g*).
 */

/**
 * @brief query the users/cdb file for information about this domain
 *
 * @param domain the domain to query
 * @param ds the domainpath field of ds will be initialized if a path is found
 * @returns negative error code or flag if domain was found
 * @retval 0 domain is not in database
 * @retval 1 domain was found
 * @retval <0 negative error code
 * @retval -EDONE the error was already handled
 *
 * Function will return 1 on success, memory for domaindir will be malloced.
 * The directory name will always end with a single '/' and be 0-terminated.
 * If the domain does not exist 0 is returned, also if no users/cdb exists.
 * On error a negative error code is returned.
 *
 * If ds already contains information about the same domain directory then
 * the already existing information is preserved.
 */
int
vget_dir(const char *domain, struct userconf *ds)
{
	int fd, i;
	char cdb_key[264];	/* maximum length of domain + 3 byte for !-\0 + padding to be sure */
	size_t cdbkeylen;
	const char *cdb_buf;
	char *cdb_mmap = NULL;
	int err;
	struct stat st;
	size_t len;

	cdbkeylen = strlen(domain) + 2;
	if (cdbkeylen + 1 >= sizeof(cdb_key))
		return -EFAULT;
	cdb_key[0] = '!';
	memcpy(cdb_key + 1, domain, cdbkeylen - 2);
	cdb_key[cdbkeylen - 1] = '-';
	cdb_key[cdbkeylen] = '\0';

	/* try to open the cdb file */
	fd = open("users/cdb", O_RDONLY);
	if (fd < 0) {
		switch (errno) {
		case ENOENT:
			/* no database, no match */
			return 0;
		case EMFILE:
		case ENFILE:
		case ENOMEM:
			return -ENOMEM;
		default:
			err_control("users/cdb");
			return -EDONE;
		}
	}

	if (fstat(fd, &st) < 0) {
		err = -errno;
		while ((close(fd) < 0) && (errno == EINTR));
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
		return err;
	}

	/* search the cdb file for our requested domain */
	cdb_buf = cdb_seekmm(fd, cdb_key, cdbkeylen, &cdb_mmap, &st);
	if (cdb_buf == NULL) {
		switch (errno) {
		case 0:
			return 0;
		case EMFILE:
		case ENFILE:
		case ENOMEM:
			return -ENOMEM;
		default:
			err_control("users/cdb");
			return -EDONE;
		}
	}

	/* format of cdb_buf is :
	 * realdomain\0uid\0gid\0path\0
	 */
	len = strlen(cdb_buf);
	cdb_buf += len + 1;	/* advance pointer past the realdomain */
	while( *cdb_buf++ != '\0' );	/* skip over the uid */
	while( *cdb_buf++ != '\0' );	/* skip over the gid */

	/* get the domain directory */
	len = strlen(cdb_buf);
	while (*(cdb_buf + len - 1) == '/')
		--len;
	i = newstr(&(ds->domainpath), len + 2);
	if (i != 0) {
		munmap(cdb_mmap, st.st_size);
		return -ENOMEM;
	}

	memcpy(ds->domainpath.s, cdb_buf, len);
	ds->domainpath.s[len] = '/';
	ds->domainpath.s[--ds->domainpath.len] = '\0';

	munmap(cdb_mmap, st.st_size);
	return 1;
}

/**
 * @brief check if a .qmail file exists for the user
 * @param ds description of the domain directory
 * @param suff1 the suffix to test (e.g. localpart), may be NULL when def is 1
 * @param len length of suff1
 * @param def which suffixes to use (logically or'ed)
 *            @arg @c 1: append "default"
 *            @arg @c 2: append suff1
 */
static int
qmexists(const struct userconf *ds, const char *suff1, const size_t len, const int def)
{
	static const char dotqm[] = ".qmail-";
	char filetmp[PATH_MAX];
	int fd;
	size_t l = ds->domainpath.len + strlen(dotqm);

	errno = ENOENT;
	if (l >= sizeof(filetmp))
		return -1;
	memcpy(filetmp, ds->domainpath.s, ds->domainpath.len);
	memcpy(filetmp + ds->domainpath.len, dotqm, strlen(dotqm));
	if (def & 2) {
		char *p;

		if (l + len >= sizeof(filetmp))
			return -1;
		memcpy(filetmp + l, suff1, len);

		/* this scans the head of the username multiple times, but it's not
		 * really worth the effort to optimize that further. memchr() is
		 * usually a pretty good optimized function, the localpart is always
		 * shorter than 1000 chars (usually _much_ shorter) and the file
		 * system access later will very likely take much longer anyway. */
		while ((p = memchr(filetmp + l, '.', len)) != NULL)
			*p = ':';

		l += len;
		if (def & 1) {
			if (l + 1 >= sizeof(filetmp))
				return -1;
			*(filetmp + l) = '-';
			l++;
		}
	}
	if (def & 1) {
		if (l + 7 >= sizeof(filetmp))
			return -1;
		memcpy(filetmp + l, "default", 7);
		l += 7;
	}
	filetmp[l] = 0;

	/* these files should not be open long enough to reach a fork, but
	 * make sure it is not accidentially leaked. */
	fd = open(filetmp, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		if ((errno == ENOMEM) || (errno == ENFILE) || (errno == EMFILE)) {
			errno = ENOMEM;
		} else if ((errno != ENOENT) && (errno != EACCES)) {
			if (err_control(filetmp) == 0)
				errno = EDONE;
		}
	}
	return fd;
}

int
user_exists(const string *localpart, const char *domain, struct userconf *ds)
{
	int userdirfd;
	struct string userdirtmp;	/* temporary storage of the pointer for userdir */
	int res;

	/* '/' is a valid character for localparts but we don't want it because
	 * it could be abused to check the existence of files */
	if (memchr(localpart->s, '/', localpart->len))
		return 0;

/* get the domain directory from "users/cdb" */
	res = vget_dir(domain, ds);
	if (res < 0) {
		errno = -res;
		return -1;
	} else if (res == 0) {
		/* the domain is not local or at least no vpopmail domain */
		return 5;
	}

	/* does directory (ds->domainpath.s)+'/'+localpart exist? */
	if (newstr(&userdirtmp, ds->domainpath.len + 2 + localpart->len) != 0) {
		userconf_free(ds);
		return -1;
	}

	memcpy(userdirtmp.s, ds->domainpath.s, ds->domainpath.len);
	memcpy(userdirtmp.s + ds->domainpath.len, localpart->s, localpart->len);
	userdirtmp.s[--userdirtmp.len] = '\0';
	userdirtmp.s[userdirtmp.len - 1] = '/';

	userdirfd = open(userdirtmp.s, O_RDONLY);
	if (userdirfd < 0) {
		int e = errno;
		int fd;

		if (e == EACCES) {
			/* The directory itself is not readable. It may still be possible to 
			 * accees specific files in it (e.g. if the mode is 0751), so keep it. */
			ds->userpath.s = userdirtmp.s;
			ds->userpath.len = userdirtmp.len;
			return 1;
		} else if ((e != ENOENT) && (errno != ENOTDIR)) {
			/* if e.g. a file with the given name exists that is no error,
			 * it just means that it is not a user directory with that name. */
			if (err_control(userdirtmp.s) != 0) {
				errno = e;
			} else {
				errno = EDONE;
			}
			free(userdirtmp.s);
			userconf_free(ds);
			return -1;
		}

		free(userdirtmp.s);

		/* does USERPATH/DOMAIN/.qmail-LOCALPART exist? */
		fd = qmexists(ds, localpart->s, localpart->len, 2);
		/* try .qmail-user-default instead */
		if ((fd < 0) && (errno == ENOENT))
			fd = qmexists(ds, localpart->s, localpart->len, 3);

		if (fd < 0) {
			char *p;

			if (errno == EACCES) {
				/* User exists */
				return 1;
			} else if (errno == ENOMEM) {
				userconf_free(ds);
				return fd;
			} else if (errno != ENOENT) {
				userconf_free(ds);
				return -1;
			}
			/* if username contains '-' there may be
			 .qmail-partofusername-default */
			p = memchr(localpart->s, '-', localpart->len);
			while (p) {
				fd = qmexists(ds, localpart->s, (p - localpart->s), 3);
				if (fd < 0) {
					if (errno == EACCES) {
						return 1;
					} else if (errno == ENOMEM) {
						userconf_free(ds);
						return fd;
					} else if (errno != ENOENT) {
						userconf_free(ds);
						return -1;
					}
				} else {
					while (close(fd)) {
						if (errno != EINTR)
							return -1;
					}
					return 4;
				}
				p = strchr(p + 1, '-');
			}

			/* does USERPATH/DOMAIN/.qmail-default exist ? */
			fd = qmexists(ds, NULL, 0, 1);
			if (fd < 0) {
				/* no local user with that address */
				if (errno == EACCES) {
					return 1;
				} else if (errno == ENOENT) {
					userconf_free(ds);
					return 0;
				} else {
					userconf_free(ds);
					return -1;
				}
			} else if (vpopbounce) {
				char buff[2*strlen(vpopbounce)+1];
				ssize_t r;
				int err = 0;

				r = read(fd, buff, sizeof(buff) - 1);
				if (r == -1) {
					
					if (err_control2(ds->domainpath.s, ".qmail-default") == 0)
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
					userconf_free(ds);
					errno = err;
					return -1;
				}

				buff[r] = 0;

				/* mail would be bounced or catched by .qmail-default */
				if (strcmp(buff, vpopbounce) == 0) {
					userconf_free(ds);
					return 0;
				} else {
					return 2;
				}
			} else {
				/* we can't tell if this is a bounce .qmail-default -> accept the mail */
				return 2;
			}
		} else {
			while (close(fd)) {
				if (errno != EINTR) {
					userconf_free(ds);
					return -1;
				}
			}
		}
	} else {
		while ((close(userdirfd) < 0) && (errno == EINTR));
		ds->userpath.s = userdirtmp.s;
		ds->userpath.len = userdirtmp.len;
	}

	return 1;
}

int
userbackend_init(void)
{
	if (lloadfilefd(open("control/vpopbounce", O_RDONLY), &vpopbounce, 0) == ((size_t)-1)) {
		int e = errno;
		err_control("control/vpopbounce");
		return e;
	}

	return 0;
}

void
userbackend_free(void)
{
	free(vpopbounce);
}

void
userconf_init(struct userconf *ds)
{
	STREMPTY(ds->domainpath);
	STREMPTY(ds->userpath);
	ds->userconf = NULL;
	ds->domainconf = NULL;
}

void
userconf_free(struct userconf *ds)
{
	free(ds->domainpath.s);
	free(ds->userpath.s);
	free(ds->userconf);
	free(ds->domainconf);

	userconf_init(ds);
}

int
userconf_load_configs(struct userconf *ds)
{
	int type, r;
	const size_t l = ds->userpath.len;

	/* load user and domain "filterconf" file */
	/* if the file is empty there is no problem, NULL is a legal value for the buffers */
	if (loadlistfd(getfile(ds, "filterconf", &type, 0), &(ds->userconf), NULL))
		return errno;

	if (type) {
		/* the domain buffer was loaded because there is no user buffer */
		ds->domainconf = ds->userconf;
		ds->userconf = NULL;
		return 0;
	}

	/* make sure this one opens the domain file: just set user path length to 0 */
	ds->userpath.len = 0;
	r = loadlistfd(getfile(ds, "filterconf", &type, 0), &(ds->domainconf), NULL);

	ds->userpath.len = l;

	return r ? errno : 0;
}

int
userconf_get_buffer(const struct userconf *ds, const char *key, char ***values, checkfunc cf, const int useglobal)
{
	int type;
	int fd;
	int r;

	fd = getfile(ds, key, &type, useglobal);

	if (fd < 0) {
		if (errno == ENOENT)
			return CONFIG_NONE;
		else
			return -errno;
	}

	r = loadlistfd(fd, values, cf);
	if (r < 0)
		return -errno;

	if (*values == NULL)
		return CONFIG_NONE;

	return type;
}

int
userconf_find_domain(const struct userconf *ds, const char *key, char *domain, const int useglobal)
{
	int type;
	int fd;
	int r;

	fd = getfile(ds, key, &type, useglobal);

	if (fd < 0) {
		if (errno == ENOENT)
			return CONFIG_NONE;
		else
			return -errno;
	}

	r = finddomainfd(fd, domain, 1);
	if ((r < 0) && (errno == 0))
		return CONFIG_NONE;
	else
		return r;
}
