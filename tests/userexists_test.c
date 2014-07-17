#include <qsmtpd/addrparse.h>
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>
#include <qsmtpd/vpop.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int err;	/**< global error counter */

/* to satisfy the linker */
const char **globalconf;
static const char *expected_err_control;

struct {
	const char *email;
	int result;
	unsigned int dirs; /* 1 = domainpath, 2 = userpath */
} users[] = {
	{
		.email = "user@example.org",
		.result = 1,
		.dirs = 3
	},
	{
		.email = "user.dot@example.org",
		.result = 1,
		.dirs = 3
	},
	{
		.email = "foo.bar@example.org",
		.result = 1,
		.dirs = 1
	},
	{
		.email = "baz@example.org",
		.result = 1,
		.dirs = 1
	},
	/* catched by .qmail-baz-default */
	{
		.email = "baz-bar@example.org",
		.result = 4,
		.dirs = 1
	},
	/* catched by .qmail-abc-def-default, this tests the case
	 * where it's not the first hyphen is the place to split */
	{
		.email = "abc-def-ghi@example.org",
		.result = 4,
		.dirs = 1
	},
	{
		.email = "bar@example.org",
		.result = 0
	},
	{
		.email = "bazz@example.org",
		.result = 0
	},
	{
		.email = "bar@example.org",
		.result = 0
	},
	/* a file with the name "someoneelse" exists, so open for the directory
	 * will fail, and no .qmail-someoneelse exists. */
	{
		.email = "someoneelse@example.org",
		.result = 0,
		.dirs = 0
	},
	/* a file with the name "someone" exists, this just means that
	 * open for the directory will fail, but the user still exists because
	 * .qmail-someone exists. */
	{
		.email = "someone@example.org",
		.result = 1,
		.dirs = 1
	},
	/* this is rejected because of the '/'. It could be fixed for cases
	 * where the address is catched by a .qmail*-default, but currently 
	 * it is forbidden. */
	{
		.email = "baz-bar/foo@example.org",
		.result = 0
	},
	/* the .qmail-default file for this domain is equal to vpopbounce */
	{
		.email = "foo@bounce.example.org",
		.result = 0
	},
	/* the .qmail-default file for this domain is not equal to vpopbounce */
	{
		.email = "foo@default.example.org",
		.result = 2,
		.dirs = 1
	},
	/* domain is not local */
	{
		.email = "bar@example.net",
		.result = 5
	},
	{
		.email = NULL
	}
};

int
err_control(const char *fn)
{
	if (expected_err_control == NULL) {
		fprintf(stderr, "unexpected call to %s(%s)\n",
			__func__, fn);
		err++;
	} else if (strcmp(fn, expected_err_control) != 0) {
		fprintf(stderr, "expected call to %s(%s), but argument was %s\n",
			__func__, expected_err_control, fn);
		err++;
	} else {
		expected_err_control = NULL;
	}

	return 0;
}

int
err_control2(const char *msg, const char *fn)
{
	fprintf(stderr, "unexpected call to %s(%s, %s)\n",
			__func__, msg, fn);
	exit(1);
}

/**
 * @brief test when users/cdb does not exist
 */
static int
test_no_cdb(void)
{
	int olddir = open(".", O_RDONLY | O_CLOEXEC);
	int ret = 0;
	int fd;

	if (olddir < 0) {
		fprintf(stderr, "can't open(.), error %i\n", errno);
		return 1;
	}

	if (chdir("users") != 0) {
		fprintf(stderr, "can't chdir(users), error %i\n", errno);
		close(olddir);
		return 1;
	}

	fd = open("users/cdb", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		fprintf(stderr, "users/users/cdb exists, test is not reliable\n");
		close(fd);
		ret++;
	} else {
		struct userconf ds;
		int r;
		const string localpart = { .s = (char *) "local", .len = strlen("local") };

		userconf_init(&ds);

		r = user_exists(&localpart, "example.com", &ds);

		userconf_free(&ds);

		if (r != 5) {
			fprintf(stderr, "user_exists() without cdb file returned %i\n", r);
			ret++;
		}
	}

	if (fchdir(olddir) != 0) {
		fprintf(stderr, "can't fchdir() back to start directory, error %i\n", errno);
		ret++;
	}

	close(olddir);

	return ret;
}

/**
 * @brief test when users/cdb is no file, but a directory
 */
static int
test_cdbdir(void)
{
	int olddir = open(".", O_RDONLY | O_CLOEXEC);
	int ret = 0;
	int fd;
	char buffer[4096];

	getcwd(buffer, sizeof(buffer));

	if (olddir < 0) {
		fprintf(stderr, "can't open(.), error %i\n", errno);
		return 1;
	}

	if (chdir("cdbdir") != 0) {
		fprintf(stderr, "can't chdir(cdbdir), error %i, cwd %s\n", errno, buffer);
		close(olddir);
		return 1;
	}

	fd = open("users/cdb/", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "users/cdbdir/users/cdb is no directory, test is not reliable, error was %i\n", errno);
		ret++;
	} else {
		struct userconf ds;
		int r;
		const string localpart = { .s = (char *) "local", .len = strlen("local") };

		close(fd);
		userconf_init(&ds);

		expected_err_control = "users/cdb";
		r = user_exists(&localpart, "example.com", &ds);

		userconf_free(&ds);

		if ((r != -1) || (errno != EDONE)) {
			fprintf(stderr, "user_exists() without cdb as directory returned %i/%i\n", r, errno);
			ret++;
		}
	}

	if (fchdir(olddir) != 0) {
		fprintf(stderr, "can't fchdir() back to start directory, error %i\n", errno);
		ret++;
	}

	close(olddir);

	return ret;
}

int
main(void)
{
	unsigned int i;

	if (userbackend_init() != 0) {
		fprintf(stderr, "error initializing vpopmail backend\n");
		return 1;
	}

	for (i = 0; users[i].email != NULL; i++) {
		struct userconf ds;
		const struct string localpart = {
			.s = (char*)users[i].email,
			.len = strchr(users[i].email, '@') - users[i].email
		};
		int r;

		userconf_init(&ds);

		r = user_exists(&localpart, strchr(users[i].email, '@') + 1, &ds);

		if (r != users[i].result) {
			fprintf(stderr, "index %u email %s: got result %i, expected %i\n",
					i, users[i].email, r, users[i].result);
			err++;
		}

		if ((users[i].dirs & 1) && (ds.domainpath.len == 0)) {
			fprintf(stderr, "index %u email %s: no domainpath found\n",
					i, users[i].email);
			err++;
		} else if (!(users[i].dirs & 1) && (ds.domainpath.len != 0)) {
			fprintf(stderr, "index %u email %s: domainpath found but not expected\n",
					i, users[i].email);
			err++;
		}

		if ((users[i].dirs & 2) && (ds.userpath.len == 0)) {
			fprintf(stderr, "index %u email %s: no userpath found\n",
					i, users[i].email);
			err++;
		} else if (!(users[i].dirs & 2) && (ds.userpath.len != 0)) {
			fprintf(stderr, "index %u email %s: userpath found but not expected\n",
					i, users[i].email);
			err++;
		}

		userconf_free(&ds);
	}

	err += test_no_cdb();
	err += test_cdbdir();

	userbackend_free();

	if (expected_err_control != NULL) {
		fprintf(stderr, "expected control file error about %s not received\n",
				expected_err_control);
		err++;
	}

	return err;
}
