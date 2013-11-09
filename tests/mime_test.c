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
	const char *badpatterns[] = {
		" (a broken text",
		"(\ra broken\ntext ",
		"(\ra broken\ntext \\)",
		NULL
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

	i = 0;
	while (badpatterns[i] != NULL) {
		const char *res = skipwhitespace(badpatterns[i], strlen(badpatterns[i]));
		if (res != NULL) {
			fprintf(stderr, "text '%s' found after '%s', but none expected\n",
					res, badpatterns[i]);
			err++;
		}
		i++;
	}

	return err;
}

static int
test_multipart_bad(void)
{
	const char *bad_lines[] = {
		"Content-Type: ", /* empty */
		"Content-Type: (comment does not end",
		"Content-Type: multipart/ju=nk", /* '=' is not allowed at this point */
		"Content-Type: multipart/mixed", /* no boundary given */
		"Content-Type: multipart/mixed;", /* no boundary given */
		"Content-Type: multipart/mixed; foo=bar", /* no boundary given */
		"Content-Type: multipart/mixed; =", /* no valid token */
		"Content-Type: multipart/mixed; foo=\"a", /* unterminated quoted parameter */
		"Content-Type: multipart/mixed; boundary=\"a", /* unterminated quoted boundary */
#if 0
		/* not tested because it terminates the program */
		"Content-Type: multipart/mixed; boundary=abcdefghijklmnopqrstuvwxyz"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
				/* boundary exceeds 70 characters */
		"Content-Type: multipart/mixed; boundary=\"ab c \"",
#endif
		NULL
	};
	int ret = 0;
	unsigned int i;

	for (i = 0; bad_lines[i] != NULL; i++) {
		cstring boundary;
		cstring line;

		STREMPTY(line);
		line.s = bad_lines[i];
		line.len = strlen(line.s);

		if (is_multipart(&line, &boundary) != -1) {
			fprintf(stderr, "bad line '%s' was not detected\n",
				bad_lines[i]);
			ret++;
		}
	}

	return ret;
}

static int
test_multipart_boundary()
{
	//* valid boundaries */
	const char *boundaries[] = {
		"gc0p4Jq0M2Yt08j34c0p",
		"boundary42",
		"42",
		NULL
	};
	//* valid boundaries that must be quoted */
	const char *qboundaries[] = {
		"gc0pJq0M:08jU534c0p",
		"simple boundary",
		"---- main boundary ----",
		"---- next message ----",
		"allvalid1: 0123456789abcdefghijklmnopqrstuvwxyz",
		"allvalid2: ABCDEFGHIJKLMNOPQRSTUVWXYZ'()+_,-./:=?",
		NULL
	};
	int ret = 0;
	unsigned int i;

	for (i = 0; boundaries[i] != NULL; i++) {
		const char *begin = "Content-Type: multipart/mixed; boundary=";
		char linebuf[128];
		cstring boundary;
		cstring line;
		int r;

		strcpy(linebuf, begin);
		strcat(linebuf, boundaries[i]);

		STREMPTY(line);
		line.s = linebuf;
		line.len = strlen(line.s);

		STREMPTY(boundary);
		r = is_multipart(&line, &boundary);

		if (r != 1)
			fprintf(stderr, "unquoted boundary (end) %u not detected as multipart, return %i\n",
					i, r);
		else if (strlen(boundaries[i]) != boundary.len)
			fprintf(stderr, "unquoted boundary (end) %u: found len %zi, expected %zi\n",
					i, boundary.len, strlen(boundaries[i]));
		else if (strncmp(boundaries[i], boundary.s, boundary.len) != 0)
			fprintf(stderr, "unquoted boundary (end) %u: found '%.*s', expected '%s'\n",
					i, (int)boundary.len, boundary.s, boundaries[i]);

		strcat(linebuf, "; foo=bar");
		line.len = strlen(line.s);

		STREMPTY(boundary);
		r = is_multipart(&line, &boundary);

		if (r != 1)
			fprintf(stderr, "unquoted boundary (middle) %u not detected as multipart, return %i\n",
					i, r);
		else if (strlen(boundaries[i]) != boundary.len)
			fprintf(stderr, "unquoted boundary (middle) %u: found len %zi, expected %zi\n",
					i, boundary.len, strlen(boundaries[i]));
		else if (strncmp(boundaries[i], boundary.s, boundary.len) != 0)
			fprintf(stderr, "unquoted boundary (middle) %u: found '%.*s', expected '%s'\n",
					i, (int)boundary.len, boundary.s, boundaries[i]);

		strcpy(linebuf, begin);
		strcat(linebuf, "\"");
		strcat(linebuf, boundaries[i]);
		strcat(linebuf, "\"");

		line.s = linebuf;
		line.len = strlen(linebuf);
		STREMPTY(boundary);

		r = is_multipart(&line, &boundary);

		if (r != 1)
			fprintf(stderr, "unquoted boundary (quoted) %u not detected as multipart, return %i\n",
				i, r);
		else if (strlen(boundaries[i]) != boundary.len)
			fprintf(stderr, "unquoted boundary (quoted) %u: found len %zi, expected %zi\n",
					i, boundary.len, strlen(boundaries[i]));
		else if (strncmp(boundaries[i], boundary.s, boundary.len) != 0)
			fprintf(stderr, "unquoted boundary (quoted) %u: found '%.*s', expected '%s'\n",
					i, (int)boundary.len, boundary.s, boundaries[i]);

		strcat(linebuf, "; foo=bar");
		line.len = strlen(line.s);

		STREMPTY(boundary);
		r = is_multipart(&line, &boundary);

		if (r != 1)
			fprintf(stderr, "unquoted boundary (quoted, middle) %u not detected as multipart, return %i\n",
					i, r);
		else if (strlen(boundaries[i]) != boundary.len)
			fprintf(stderr, "unquoted boundary (quoted, middle) %u: found len %zi, expected %zi\n",
					i, boundary.len, strlen(boundaries[i]));
		else if (strncmp(boundaries[i], boundary.s, boundary.len) != 0)
			fprintf(stderr, "unquoted boundary (quoted, middle) %u: found '%.*s', expected '%s'\n",
					i, (int)boundary.len, boundary.s, boundaries[i]);

	}
	
	for (i = 0; qboundaries[i] != NULL; i++) {
		const char *begin = "Content-Type: multipart/mixed; boundary=";
		char linebuf[128];
		cstring boundary;
		cstring line;
		int r;

		strcpy(linebuf, begin);
		strcat(linebuf, "\"");
		strcat(linebuf, qboundaries[i]);
		strcat(linebuf, "\"");

		line.s = linebuf;
		line.len = strlen(linebuf);
		STREMPTY(boundary);

		r = is_multipart(&line, &boundary);

		if (r != 1)
			fprintf(stderr, "unquoted boundary (quoted) %u not detected as multipart, return %i\n",
				i, r);
		else if (strlen(qboundaries[i]) != boundary.len)
			fprintf(stderr, "unquoted boundary (quoted) %u: found len %zi, expected %zi\n",
					i, boundary.len, strlen(qboundaries[i]));
		else if (strncmp(qboundaries[i], boundary.s, boundary.len) != 0)
			fprintf(stderr, "unquoted boundary (quoted) %u: found '%.*s', expected '%s'\n",
					i, (int)boundary.len, boundary.s, qboundaries[i]);

		strcat(linebuf, "; foo=bar");
		line.len = strlen(line.s);

		STREMPTY(boundary);
		r = is_multipart(&line, &boundary);

		if (r != 1)
			fprintf(stderr, "unquoted boundary (quoted, middle) %u not detected as multipart, return %i\n",
					i, r);
		else if (strlen(qboundaries[i]) != boundary.len)
			fprintf(stderr, "unquoted boundary (quoted, middle) %u: found len %zi, expected %zi\n",
					i, boundary.len, strlen(qboundaries[i]));
		else if (strncmp(qboundaries[i], boundary.s, boundary.len) != 0)
			fprintf(stderr, "unquoted boundary (quoted, middle) %u: found '%.*s', expected '%s'\n",
					i, (int)boundary.len, boundary.s, qboundaries[i]);

	}
	
	return ret;
}

int
main(void)
{
	int err = 0;

	err += test_ws();
	err += test_multipart_bad();
	err += test_multipart_boundary();

	return err;
}
