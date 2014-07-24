/** \file vpop.c
 * \brief function to get domain directory of vpopmail virtual domain
 */

#include <qsmtpd/vpop.h>

#include <cdb.h>
#include <control.h>
#include <diropen.h>
#include <qsmtpd/addrparse.h>
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>
#include <qsmtpd/userfilters.h>
#include <sstring.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static char *vpopbounce;			/**< the bounce command in vpopmails .qmail-default */
static struct userconf uconf;			/**< global userconfig cache */

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
 * @param ds pointer to userconf struct holding the domain info
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
	int fd;
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
	fd = open("users/cdb", O_RDONLY | O_CLOEXEC);
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
		close(fd);
		return err;
	}
	if (!st.st_size) {
		err = 0;
		if (close(fd) < 0)
			err = -errno;
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

	/* ds->domainpath.s includes a trailing '/' so it is one byte longer */
	if ((len + 1 != ds->domainpath.len) || (memcmp(ds->domainpath.s, cdb_buf, len) != 0)) {
		char *tmp;

		tmp = realloc(ds->domainpath.s, len + 2);
		if (tmp == NULL) {
			munmap(cdb_mmap, st.st_size);
			return -ENOMEM;
		}

		/* the domain has changed, clear all contents */
		ds->domainpath.s = NULL;
		userconf_free(ds);

		ds->domainpath.s = tmp;
		ds->domainpath.len = len + 1;
		memcpy(ds->domainpath.s, cdb_buf, len);
		ds->domainpath.s[len] = '/';
		ds->domainpath.s[len + 1] = '\0';
	} else {
		/* the domainpath is the same as already in ds, keep it. Just wipe the user config. */
		if (ds->userdirfd >= 0) {
			close(ds->userdirfd);
			ds->userdirfd = -1;
		}
		free(ds->userconf);
		ds->userconf = NULL;
	}

	munmap(cdb_mmap, st.st_size);
	return 1;
}

/**
 * @brief check if a .qmail file exists for the user
 * @param domaindirfd descriptor of the domain directory
 * @param suff1 the suffix to test (e.g. localpart), may be NULL when def is 1
 * @param len length of suff1
 * @param def which suffixes to use (logically or'ed)
 *            @arg @c 1: append "default"
 *            @arg @c 2: append suff1
 * @param fd file descriptor of .qmail file is returned here if argument is not NULL
 * @return if the file exists
 * @retval 0 file does not exist
 * @retval 1 file exists
 * @retval -1 error opening the file (errno is set)
 */
static int
qmexists(int domaindirfd, const char *suff1, const size_t len, const int def, int *fd)
{
	static const char dotqm[] = ".qmail-";
	char filetmp[PATH_MAX];
	int tmpfd;
	size_t l = strlen(dotqm);

	errno = ENOENT;
	if (l >= sizeof(filetmp))
		return -1;
	memcpy(filetmp, dotqm, l);

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
	tmpfd = openat(domaindirfd, filetmp, O_RDONLY | O_CLOEXEC);
	if (tmpfd <= 0) {
		switch (errno) {
		case ENOMEM:
		case ENFILE:
		case EMFILE:
			errno = ENOMEM;
			return -1;
		case EACCES:
			return 1;
		case ENOENT:
		case EISDIR:
			return 0;
		default:
			tmpfd = errno;
			if (err_control(filetmp) == 0)
				errno = EDONE;
			else
				errno = tmpfd;
			return -1;
		}
	} else {
		if (fd == NULL)
			close(tmpfd);
		else
			*fd = tmpfd;
		return 1;
	}
}

int
user_exists(const string *localpart, const char *domain, struct userconf *dsp)
{
	int res, e;
	struct userconf *ds = (dsp == NULL) ? &uconf : dsp;
	int dfd, fd;
	char *p;

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

	/* check if the domain directory exists */
	/* FIXME: change this to -1 to enforce absolute path */
	dfd = get_dirfd(AT_FDCWD, ds->domainpath.s);
	if (dfd < 0) {
		e = errno;

		switch (e) {
		case EMFILE:
		case ENFILE:
		case ENOMEM:
			userconf_free(ds);
			errno = e;
			return -1;
		case ENOENT:
		case ENOTDIR:
			userconf_free(ds);
			return 0;
		case EACCES:
			/* The directory exists, but we can not look into it. Assume the
			 * user exists. */
			return 1;
		default:
			if (err_control(ds->domainpath.s) == 0)
				e = EDONE;
			userconf_free(ds);
			errno = e;
			return -1;
		}
	} else {
		/* this else isn't strictly neccessary, it's here to limit the lifetime
		 * of buf */
		char fnbuf[localpart->len + 1];

		memcpy(fnbuf, localpart->s, localpart->len);
		fnbuf[localpart->len] = '\0';

		/* does directory (ds->domainpath.s)+'/'+localpart exist? */
		ds->userdirfd = get_dirfd(dfd, fnbuf);
		if (ds->userdirfd >= 0) {
			close(dfd);
			return 1;
		} else if ((errno != ENOENT) && (errno != ENOTDIR)) {
			/* if e.g. a file with the given name exists that is no error,
			 * it just means that it is not a user directory with that name. */
			e = errno;

			close(dfd);
			if (err_control2(ds->domainpath.s, fnbuf) == 0)
				e = EDONE;
			userconf_free(ds);
			errno = e;
			return -1;
		}
	}

	if (errno == EACCES) {
		/* The directory itself is not readable, so user configuration files
		 * inside it can't be accessed. */
		close(dfd);
		return 1;
	}

	/* does USERPATH/DOMAIN/.qmail-LOCALPART exist? */
	res = qmexists(dfd, localpart->s, localpart->len, 2, NULL);
	/* try .qmail-user-default instead */
	if (res == 0)
		res = qmexists(dfd, localpart->s, localpart->len, 3, NULL);

	if (res > 0) {
		close(dfd);
		return 1;
	} else if (res < 0) {
		res = errno;
		userconf_free(ds);
		close(dfd);
		errno = res;
		return -1;
	}

	/* if username contains '-' there may be
	 * .qmail-partofusername-default */
	p = memchr(localpart->s, '-', localpart->len);
	while (p) {
		res = qmexists(dfd, localpart->s, (p - localpart->s), 3, NULL);
		if (res > 0) {
			close(dfd);
			return 4;
		} else if (res < 0) {
			res = errno;
			userconf_free(ds);
			close(dfd);
			errno = res;
			return -1;
		}
		p = strchr(p + 1, '-');
	}

	/* does USERPATH/DOMAIN/.qmail-default exist ? */
	res = qmexists(dfd, NULL, 0, 1, &fd);
	e = errno;
	close(dfd);
	if (res == 0) {
		/* no local user with that address */
		userconf_free(ds);
		return 0;
	} else if (res < 0) {
		userconf_free(ds);
		errno = e;
		return -1;
	} else if (vpopbounce) {
		char buff[2*strlen(vpopbounce)+1];
		ssize_t r;

		e = 0;
		r = read(fd, buff, sizeof(buff) - 1);
		if (r < 0) {
			if (err_control2(ds->domainpath.s, ".qmail-default") == 0)
				e = EDONE;
			else
				e = errno;
		}
		if ((close(fd) != 0) && (e == 0))
			e = errno;
		if (e != 0) {
			userconf_free(ds);
			errno = e;
			return -1;
		}

		buff[r] = '\0';

		/* mail would be bounced or catched by .qmail-default */
		if (strcmp(buff, vpopbounce) == 0) {
			userconf_free(ds);
			return 0;
		} else {
			return 2;
		}
	} else {
		/* we can't tell if this is a bounce .qmail-default -> accept the mail */
		close(fd);
		return 2;
	}
}

int
userbackend_init(void)
{
	if (lloadfilefd(openat(controldir_fd, "vpopbounce", O_RDONLY | O_CLOEXEC), &vpopbounce, 0) == ((size_t)-1)) {
		int e = errno;
		err_control("control/vpopbounce");
		return e;
	}

	userconf_init(&uconf);

	return 0;
}

void
userbackend_free(void)
{
	userconf_free(&uconf);

	free(vpopbounce);
}

void
userconf_init(struct userconf *ds)
{
	STREMPTY(ds->domainpath);
	ds->userconf = NULL;
	ds->domainconf = NULL;
	ds->userdirfd = -1;
}

void
userconf_free(struct userconf *ds)
{
	free(ds->domainpath.s);
	free(ds->userconf);
	free(ds->domainconf);
	if (ds->userdirfd >= 0)
		close(ds->userdirfd);

	userconf_init(ds);
}

int
userconf_load_configs(struct userconf *ds)
{
	int type, r;
	const int ufd = ds->userdirfd;

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
	ds->userdirfd = -1;
	r = loadlistfd(getfile(ds, "filterconf", &type, 0), &(ds->domainconf), NULL);

	ds->userdirfd = ufd;

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
