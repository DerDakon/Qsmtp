/** \file fmt_test.c
 \brief testcase for printing numbers to a buffer
 */

#include "fmt.h"
#include "test_io/testcase_io.h"

#include <stdio.h>
#include <string.h>

static int
compare(const unsigned long value)
{
	char buf[ULSTRLEN + 3];
	char cbuf[ULSTRLEN + 3];
	int err = 0;

	snprintf(cbuf, sizeof(cbuf) - 1, "%lu", value);
	ultostr(value, buf);

	if (strlen(buf) >= ULSTRLEN) {
		fprintf(stderr, "printing value %lu does not fit into buffer\n", value);
		err++;
	}
	if (strcmp(cbuf, buf) != 0) {
		fprintf(stderr, "formatted values for %lu do not match: c lib: %s ultostr(): %s\n", value, cbuf, buf);
		err++;
	}

	return err;
}

int
main(void)
{
	int err = 0;
	int i;

	err += compare(0);
	err += compare(1);

	for (i = 0; i < 9; i++) {
		int j = 10;
		int k;

		for (k = i; k > 0; k--)
			j *= 10;

		err += compare(j - 1);
		err += compare(j);
		err += compare(j + 1);
	}

	err += compare((unsigned long)-1);

	return err;
}