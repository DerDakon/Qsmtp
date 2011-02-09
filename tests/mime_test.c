#include "mime.h"
#include "test_io/testcase_io.h"

#include <stdio.h>
#include <string.h>

static int
test_ws()
{
	int err = 0;
	const struct {
		const char *raw;
		const char *result;
	} patterns[] = {
		{
			.raw = "a b",
			.result = "a b"
		},
		{
			.raw = "  a",
			.result = "a"
		},
		{
			.raw = "\t\ta",
			.result = "a"
		},
		{
			.raw = "\t \t\n a",
			.result = "a"
		},
		{
			.raw = "\t \t\n\ta",
			.result = "a"
		},
		{
			.raw = "\t \t\n \ta",
			.result = "a"
		},
		{
			.raw = "\t \t\n\t a",
			.result = "a"
		},
		{
			.raw = "\t  ",
			.result = ""
		},
		{
			.raw = " (comment) \r\n\t (comment)a",
			.result = "a"
		},
		{
			.raw = " (comment (nested)) a",
			.result = "a"
		},
		{
			.raw = " (comment \r\n\t with wrap)a",
			.result = "a"
		},
		{
			.raw = " (comment \r\n\t wrapped comment)a",
			.result = "a"
		},
		{
			.raw = " (comment\\) \r\n\t still comment)a",
			.result = "a"
		},
		{
			.raw = "(comment) \\(no comment\\) a",
			.result = "\\(no comment\\) a"
		},
		{
			.raw = NULL,
			.result = NULL
		}
	};
	unsigned int i = 0;

	while (patterns[i].raw != NULL) {
		const char *res = skipwhitespace(patterns[i].raw, strlen(patterns[i].raw));
		if (res == NULL) {
			fprintf(stderr, "no text found after '%s', but expected '%s'\n",
					patterns[i].raw, patterns[i].result);
			err++;
		} else if (strcmp(res, patterns[i].result) != 0) {
			fprintf(stderr, "test after '%s' is '%s', but expected was '%s'\n",
					patterns[i].raw, res, patterns[i].result);
			err++;
		}
		i++;
	}

	return err;
}

int
main(void)
{
	int err = 0;

	err += test_ws();

	return err;
}

