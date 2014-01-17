#include <qsmtpd/addrparse.h>
#include <qsmtpd/userconf.h>
#include <qsmtpd/vpop.h>

#include <stdio.h>
#include <string.h>

/* to satisfy the linker */
const char **globalconf;

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
	fprintf(stderr, "unexpected call to %s(%s)\n",
		__func__, fn);
	exit(1);
}

int
err_control2(const char *msg, const char *fn)
{
	fprintf(stderr, "unexpected call to %s(%s, %s)\n",
			__func__, msg, fn);
	exit(1);
}

int
main(void)
{
	int ret = 0;
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

		userconf_init(&ds);

		const int r = user_exists(&localpart, strchr(users[i].email, '@') + 1, &ds);

		if (r != users[i].result) {
			fprintf(stderr, "index %u email %s: got result %i, expected %i\n",
					i, users[i].email, r, users[i].result);
			ret++;
		}

		if ((users[i].dirs & 1) && (ds.domainpath.len == 0)) {
			fprintf(stderr, "index %u email %s: no domainpath found\n",
					i, users[i].email);
			ret++;
		} else if (!(users[i].dirs & 1) && (ds.domainpath.len != 0)) {
			fprintf(stderr, "index %u email %s: domainpath found but not expected\n",
					i, users[i].email);
			ret++;
		}

		if ((users[i].dirs & 2) && (ds.userpath.len == 0)) {
			fprintf(stderr, "index %u email %s: no userpath found\n",
					i, users[i].email);
			ret++;
		} else if (!(users[i].dirs & 2) && (ds.userpath.len != 0)) {
			fprintf(stderr, "index %u email %s: userpath found but not expected\n",
					i, users[i].email);
			ret++;
		}

		userconf_free(&ds);
	}

	userbackend_free();

	return ret;
}
