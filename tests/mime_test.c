#include <qremote/mime.h>
#include <qremote/qremote.h>
#include <sstring.h>
#include "test_io/testcase_io.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

void
write_status(const char *str)
{
	puts(str);
}

static int
test_sst(void)
{
	struct string st;
	int ret = 0, i;
	char ch;

	st.len = 1;
	st.s = &ch;

	i = newstr(&st, 0);
	if (i != 0) {
		fprintf(stderr, "initializing a new sstring with length 0 returned %i\n", i);
		ret++;
	}
	if (st.len != 0) {
		fprintf(stderr, "initializing a new sstring with length 0 did not clear len\n");
		ret++;
	}
	if (st.len != 0) {
		fprintf(stderr, "initializing a new sstring with length 0 did not clear s\n");
		ret++;
	}

	i = newstr(&st, 10);
	if ((i < 0) && (errno == ENOMEM))
		exit(ENOMEM);

	if (st.len != 10) {
		fprintf(stderr, "initializing a new sstring with length 10 set len to %zu\n", st.len);
		ret++;
	}

	if ((st.s == NULL) || (st.s == &ch)) {
		fprintf(stderr, "initializing a new sstring with length 10 did not properly set s\n");
		return ++ret;
	}

	/* write to the memory, this allows valgrind and friends to catch errors */
	memset(st.s, '.', 10);
	free(st.s);

	return ret;
}

static int
test_ws(void)
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
		"Content-Type: multipart/mixed  \t", /* no boundary given */
		"Content-Type: multipart/mixed;", /* no boundary given */
		"Content-Type: multipart/mixed; foo=bar", /* no boundary given */
		"Content-Type: multipart/mixed; =", /* no valid token */
		"Content-Type: multipart/mixed; foo=\"a", /* unterminated quoted parameter */
		"Content-Type: multipart/mixed; boundary=\"a", /* unterminated quoted boundary */
		"Content-Type: multipart/mixed; foo=\"A\"a", /* non-whitespace after quoted string */
		"Content-Type: multipart/mixed; foo=A:a", /* colon not permitted here */
		"Content-Type: multipart/mixed; (", /* unfinished comment */
#if 0
		/* not tested because it terminates the program */
		"Content-Type: multipart/mixed; boundary=abcdefghijklmnopqrstuvwxyz"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
				/* boundary exceeds 70 characters */
		"Content-Type: multipart/mixed; boundary=\"ab c \"",
#endif
		NULL
	};
	const char *good_lines[] = {
		"Content-Type: multipart/mixed; boundary=a", /* ascii, everything is fine */
		"Content-Type: multipart/mixed; boundary=\"a\"", /* ascii, but quoted */
		"Content-Type: multipart/mixed;\tboundary=a\t", /* enclosed in tabs */
		"Content-Type: multipart/mixed; boundary=a ", /* enclosed in spaces */
		NULL
	};
	int ret = 0;
	unsigned int i;

	for (i = 0; bad_lines[i] != NULL; i++) {
		cstring boundary;
		cstring line;
		int r;

		STREMPTY(line);
		line.s = bad_lines[i];
		line.len = strlen(line.s);

		r = is_multipart(&line, &boundary);
		if (r != -1) {
			fprintf(stderr, "bad line '%s' was not detected, result was %i\n",
				bad_lines[i], r);
			ret++;
		}
	}

	for (i = 0; good_lines[i] != NULL; i++) {
		cstring boundary;
		cstring line;
		int r;

		STREMPTY(line);
		line.s = good_lines[i];
		line.len = strlen(line.s);

		r = is_multipart(&line, &boundary);
		if (r != 1) {
			fprintf(stderr, "good line '%s' was not detected, result was %i\n",
				good_lines[i], r);
			ret++;
		} else if ((boundary.len != 1) || (strncmp(boundary.s, "a", boundary.len) != 0)) {
			fprintf(stderr, "good line '%s' returned boundary len %zu string '%s'\n",
				good_lines[i], boundary.len, boundary.s);
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
		const char *sbegin[] = {
			"Content-Type: multipart/mixed; boundary=",
			"Content-Type: multipart/mixed; "
				"foo=bar; boundaryfoo=bar; boundary=",
			NULL
		};
		unsigned int j;

		for (j = 0; sbegin[j] != NULL; j++) {
			const char *begin = sbegin[j];
			char linebuf[128];
			cstring boundary;
			cstring line;
			int r;

			assert(sizeof(linebuf) > strlen(begin) + 2 + strlen(boundaries[i]));
			strncpy(linebuf, begin, sizeof(linebuf));
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

			strncpy(linebuf, begin, sizeof(linebuf));
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
	}

	for (i = 0; qboundaries[i] != NULL; i++) {
		const char *begin = "Content-Type: multipart/mixed; boundary=";
		char linebuf[128];
		cstring boundary;
		cstring line;
		int r;

		strcpy(linebuf, begin);
		strcat(linebuf, "\"");
		assert(strlen(qboundaries[i]) < sizeof(linebuf) - strlen(linebuf) - 1);
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

	err += test_sst();
	err += test_ws();
	err += test_multipart_bad();
	err += test_multipart_boundary();

	return err;
}
