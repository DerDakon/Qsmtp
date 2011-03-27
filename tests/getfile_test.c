#include "userfilters.h"

#include "control.h"

#include <stdio.h>
#include <string.h>

char **globalconf;

static const char *confdata[] = {
		"simple",
		"one=1",
		"two=2",
		"invalid=invalid",
		NULL
};

static struct userconf ds;

static int
test_flag(const char *flag, const long expect)
{
	int t = -1;
	long r = getsetting(&ds, flag, &t);

	if ((r != expect) || (t != 1)) {
		fprintf(stderr, "searching for '%s' should return %li, but returned %li (type %i)\n",
				flag, expect, r, t);
		return 1;
	}

	return 0;
}

int main()
{
	int err = 0;

	memset(&ds, 0, sizeof(ds));
	ds.domainconf = (char **)confdata;

	err += test_flag("simple", 1);
	err += test_flag("one", 1);
	err += test_flag("two", 2);
	err += test_flag("nonexistent", 0);
	err += test_flag("invalid", -1);

	return err;
}
