#include <qsmtpd/addrparse.h>
#include <qsmtpd/userconf.h>
#include <qsmtpd/vpop.h>

#include <assert.h>
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
	{
		.email = "baz-bar@example.org",
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
	{
		.email = NULL
	}
};

int
err_control(const char *fn)
{
	fprintf(stderr, "unexpected call to %s(%s)\n",
			__func__, fn);
	assert(0);
}

int
main(void)
{
	int ret = 0;
	unsigned int i;

	for (i = 0; users[i].email != NULL; i++) {
		struct userconf ds;
		const struct string localpart = {
			.s = (char*)users[i].email,
			.len = strchr(users[i].email, '@') - users[i].email
		};

		userconf_init(&ds);

		const int r = user_exists(&localpart, strchr(users[i].email, '@') + 1, &ds);

		if (r != users[i].result) {
			fprintf(stderr, "index %u: got result %i, expected %i\n",
					i, r, users[i].result);
			ret++;
		}

		if ((users[i].dirs & 1) && (ds.domainpath.len == 0)) {
			fprintf(stderr, "index %u: no domainpath found\n", i);
			ret++;
		} else if (!(users[i].dirs & 1) && (ds.domainpath.len != 0)) {
			fprintf(stderr, "index %u: domainpath found but not expected\n", i);
			ret++;
		}

		if ((users[i].dirs & 2) && (ds.userpath.len == 0)) {
			fprintf(stderr, "index %u: no userpath found\n", i);
			ret++;
		} else if (!(users[i].dirs & 2) && (ds.userpath.len != 0)) {
			fprintf(stderr, "index %u: userpath found but not expected\n", i);
			ret++;
		}

		userconf_free(&ds);
	}

	return ret;
}
