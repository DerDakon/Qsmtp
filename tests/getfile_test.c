#include "userfilters.h"

#include "control.h"

#include <stdio.h>
#include <string.h>

char **globalconf;

static const char *dconfdata[] = {
		"simple",
		"one=1",
		"two=2",
		"twentytwo=22",
		"twenty=20",
		"domain=42",
		"invalid=invalid",
		NULL
};

static const char *uconfdata[] = {
		"domain=-1",
		NULL
};

static struct userconf ds;

static int
test_flag(const char *flag, const long expect, const int expecttype)
{
	int t = -1;
	long r = getsetting(&ds, flag, &t);

	if ((r != expect) || (t != expecttype)) {
		fprintf(stderr, "searching for '%s' should return %li (type %i), "
				"but returned %li (type %i)\n",
				flag, expect, expecttype, r, t);
		return 1;
	}

	return 0;
}

int main()
{
	int err = 0;

	memset(&ds, 0, sizeof(ds));
	ds.domainconf = (char **)dconfdata;
	ds.userconf = (char **)uconfdata;

	err += test_flag("simple", 1, 1);
	err += test_flag("one", 1, 1);
	err += test_flag("two", 2, 1);
	err += test_flag("nonexistent", 0, 1);
	err += test_flag("invalid", -1, 1);
	err += test_flag("twenty", 20, 1);
	err += test_flag("twentytwo", 22, 1);
	err += test_flag("domain", 0, 0);

	return err;
}
