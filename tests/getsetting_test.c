#include <qsmtpd/userfilters.h>

#include "control.h"

#include <stdio.h>
#include <string.h>

const char **globalconf;

static const char *dconfdata[] = {
		"simple",
		"one=1",
		"two=2",
		"twentytwo=22",
		"twenty=20",
		"domain=42",
		"invalid=invalid",
		"forcenull=-2",
		NULL
};

static const char *uconfdata[] = {
		"domain=-1",
		NULL
};

static const char *gconfdata[] = {
		"forcenull=2",
		"global=3",
		"globalforcenull=-3",
		NULL
};

static struct userconf ds;

static int
test_flag(const char *flag, const long expect, const int expecttype)
{
	int t = -1;
	long r;

	if (expecttype != 2) {
		r = getsetting(&ds, flag, &t);
		if ((r != expect) || (t != expecttype)) {
			fprintf(stderr, "searching for '%s' with getsetting() should return "
					"%li (type %i), but returned %li (type %i)\n",
					flag, expect, expecttype, r, t);
			return 1;
		}
	}

	r = getsettingglobal(&ds, flag, &t);

	if ((r != expect) || (t != expecttype)) {
		fprintf(stderr, "searching for '%s' with getsettingglobal() should return "
				"%li (type %i), but returned %li (type %i)\n",
				flag, expect, expecttype, r, t);
		return 1;
	}

	return 0;
}

int main()
{
	int err = 0;
	long r;
	int t;

	memset(&ds, 0, sizeof(ds));
	ds.domainconf = (char **)dconfdata;
	ds.userconf = (char **)uconfdata;

	err += test_flag("domain", 0, 0);
	err += test_flag("simple", 1, 1);
	err += test_flag("one", 1, 1);
	err += test_flag("two", 2, 1);
	err += test_flag("invalid", -1, 1);
	err += test_flag("forcenull", 0, 1);

	/* now without userconfig, checks other branches */
	ds.userconf = NULL;

	err += test_flag("twenty", 20, 1);
	err += test_flag("twentytwo", 22, 1);

	/* now with user and global config */
	globalconf = gconfdata;
	ds.userconf = (char **)uconfdata;
	err += test_flag("forcenull", 0, 1);
	err += test_flag("global", 3, 2);
	err += test_flag("nonexistent", 0, 2);
	err += test_flag("globalforcenull", 0, 2);

	t = -1;
	r = getsetting(&ds, "nonexistent", &t);
	if ((r != 0) || (t != 1)) {
		fprintf(stderr, "searching for 'nonexistent' with getsetting() should return "
				"0 (type 1), but returned %li (type %i)\n", r, t);
		return 1;
	}

	return err;
}
