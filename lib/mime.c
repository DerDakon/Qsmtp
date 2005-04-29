#include <strings.h>
#include <string.h>
#include "mime.h"
#include "sstring.h"

/**
 * skipwhitespace - skip whitespaces
 *
 * @line: header field
 * @len: length of data, must be > 0
 *
 * returns: pointer to first character after whitespace, NULL on syntax error (e.g. unfinished comment)
 *
 * This function skips whitespace from the current position. If a RfC 822 section 2.8 style comment is
 * found this is also skipped. If a newline is encountered before a non-whitespace and non-comment
 * character it is also skipped, including all following whitespace.
 *
 * If it returns (line + len) everything from line until end of data block is a comment
 *
 * line has to be a valid (but unparsed) and may be a folded header line. For this it has to meet this
 * constraints:
 *  * it has to end with CR, LF or CRLF
 *  * it may have CR, LF or CRLF in the middle, but this has to be directly followed by either ' ' or '\t'
 */
const char * __attribute__ ((pure))
skipwhitespace(const char *line, const size_t len)
{
	int ws = 0;	/* found at least one whitespace */
	size_t l = len;	/* -1: make sure to stop before end of data, assume it ends with CRLF */
	const char *c = line;

	/* skip whitespaces */
	while ((*c == ' ') || (*c == '\t')) {
		c++;
		if (!--l)
			return c;
		ws = 1;
	}

	if (!ws)
		return c;

	/* RfC 822 Section 2.8 */
	if (*c == ';') {
		c++;
		if (!--l)
			return c;

		while ((*c != '\r') || (*c != '\n')) {
			c++;
			if (!--l)
				return c;
		}
		if (*c == '\r') {
			c++;
			if (--l && (*c == '\n')) {
				l--;
				c++;
			}
		}
	}

	for (;;) {
		int brace = 0;

		/* skip whitespaces */
		if ((*c == ' ') || (*c == '\t')) {
			while ((*c == ' ') || (*c == '\t')) {
				c++;
				if (!--l)
					return c;
			}
		}

		ws = 0;

		if (*c == '\r') {
			c++;
			l--;
			ws = 1;
		}
		if (l && (*c == '\n')) {
			c++;
			l--;
			ws = 1;
		}
		if (ws)
			continue;

		if ((!--l) || (*c != '(')) {
			return c;
		}

		do {
			if (!--l)
				return NULL;
			if (*c == '(') {
				if (*(c - 1) != '\\')
					brace++;
			} else if (*c == ')') {
				if (*(c - 1) != '\\')
					brace--;
			} else if ((*c == '\r') || (*c == '\n')) {
				ws = 0;
			}
			c++;
		} while (brace);
	}
}

/**
 * is_multipart: scan "Content-Type" header line and check if type is multipart/(*) or message/(*)
 *
 * @line: header field
 *
 * returns: 1 if line contains multipart/(*) or message/(*) declaration, 0 if other type, -1 on syntax error
 */
int __attribute__ ((pure))
is_multipart(const struct string *line)
{
	const char *ch;

	if (!line->len)
		return 0;

	if ( (ch = skipwhitespace(line->s + 13, line->len - 13)) == NULL)
		return -1;

	if (ch == line->s + line->len)
		return -1;

	if (!strncasecmp(ch, "multipart/", 10) || !strncasecmp(ch, "message/", 8)) {
#warning FIXME: scan rest of line for syntax errors
		return 1;
	}

	return 0;
}

/**
 * getfieldlen - get length of a MIME header field, even if it is folded
 *
 * @msg: message data to scan
 * @len: length of data
 *
 * returns: length of header field, 0 if field does not end until end of data
 */
size_t __attribute__ ((pure))
getfieldlen(const char *msg, const size_t len)
{
	const char *cr = msg;
	size_t r = len;

	do {
		while (r && (*cr != '\r') && (*cr != '\n')) {
			cr++;
			r--;
		}
		if (r && (*cr == '\r')) {
			cr++;
			r--;
		}
		if (r && (*cr == '\n')) {
			cr++;
			r--;
		}
	} while (r && ((*cr == ' ') || (*cr == '\t')));

	return ((*(cr - 1) == '\n') || (*(cr - 1) == '\r')) ? len - r : 0;
}
