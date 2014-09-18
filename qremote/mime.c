/** @file mime.c
  \brief MIME handling functions
 */

#include <qremote/mime.h>

#include <mime_chars.h>
#include <netio.h>
#include <qremote/qrdata.h>
#include <qremote/qremote.h>
#include <sstring.h>

#include <assert.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

/**
 * skip whitespaces in header line
 *
 * @param line header field
 * @param len length of data, must be > 0
 * @return pointer to first character after whitespace
 * @retval NULL syntax error (e.g. unfinished comment)
 *
 * This function skips whitespace and comments from the current position. If a newline is encountered
 * before a non-whitespace and non-comment character it is also skipped, including all following whitespace.
 *
 * If it returns (line + len) everything from line until end of data block is a comment
 *
 * line has to be a valid (but unparsed) and may be a folded header line. For this it has to meet this
 * constraints:
 * -it has to end with CR, LF or CRLF
 * -it may have CR, LF or CRLF in the middle, but this has to be directly followed by either SPACE or TAB
 */
const char *
skipwhitespace(const char *line, const size_t len)
{
	size_t l = len;
	const char *c = line;

	while (l != 0) {
		int brace = 0;
		int ws = 0;	/* found at least one whitespace */

		/* skip whitespaces */
		if ((*c == ' ') || (*c == '\t')) {
			while ((*c == ' ') || (*c == '\t')) {
				c++;
				if (!--l)
					return c;
			}
		}

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

		l++;

		do {
			if (!--l)
				return NULL;
			if ((*c == '(') && (*(c - 1) != '\\'))
				brace++;
			else if ((*c == ')') && (*(c - 1) != '\\'))
				brace--;
			c++;
		} while (brace);
	}

	return c;
}

/**
 * get length of MIME header token as defined in RfC 2045, section 5.1
 *
 * @param line header line to scan
 * @param len length of line
 * @return length of parameter
 * @retval 0 syntax error
 */
static size_t __attribute__ ((pure)) __attribute__ ((nonnull(1)))
mime_token(const char *line, const size_t len)
{
	size_t i = 0;

	for (; i < len; i++) {
		if ((line[i] == ';') || (line[i] == '=')) {
			return i;
		}
		if ((line[i] == ' ') || (line[i] == '\t') ||
					(line[i] == '\r') || (line[i] == '\n')) {
			const char *e = skipwhitespace(line + i, len - i);

			return (e == line + len) ? i : 0;
		}
		if ((line[i] <= 32) || TSPECIAL(line[i])) {
			return 0;
		}
	}
	return i;
}

/**
 * get length of MIME header parameter
 *
 * @param line header line to scan
 * @param len length of line
 * @return length of parameter
 * @retval 0 syntax error
 */
static size_t __attribute__ ((pure)) __attribute__ ((nonnull(1)))
mime_param(const char *line, const size_t len)
{
	size_t i = mime_token(line, len);

	if (!i || (i == len) || (line[i] != '='))
		return 0;

	i++;
	if (line[i] == '"') {
		for (i++; i < len; i++) {
			if ((line[i] == '"') && (line[i - 1] != '\\')) {
				break;
			}
		}

		/* the end of quote has not been found */
		if (i == len)
			return 0;

		/* skip over closing quote */
		i++;

		/* end of string */
		if (i == len)
			return i;

		/* if no end quote has been found or something invalid follows fail */
		if ((line[i] != ';') && (line[i] != '(') && !WSPACE(line[i]))
			return 0;

		return i;
	} else {
		size_t j;

		if (WSPACE(line[i]))
			return 0;
		j = mime_token(line + i, len - i);

		i += j;
		if ((i == len) || (line[i] == ';') || WSPACE(line[i]))
			return i;
		return 0;
	}
}

/**
 * scan "Content-Type" header line and check if type is multipart/(*)
 *
 * @param line header field
 * @param boundary reference to boundary is stored here
 * @retval 1 line contains multipart/(*) declaration
 * @retval 0 other type
 * @retval -1 syntax error
 */
int
is_multipart(const cstring *line, cstring *boundary)
{
	const char *ch;

	if (!line->len)
		return 0;

	if ( (ch = skipwhitespace(line->s + 13, line->len - 13)) == NULL)
		return -1;

	if (ch == line->s + line->len)
		return -1;

	STREMPTY(*boundary);

	if (!strncasecmp(ch, "multipart/", strlen("multipart/"))) {
		size_t i = strlen("multipart/"), j;

		j = mime_token(ch + i, line->len - (ch - line->s) - i);
		i += j;
		if (!j || (ch[i] == '='))
			return -1;
		if (ch[i] != ';') {
			return -1;
		}
		i++;
		while (1) {
			ch += i;
			ch = skipwhitespace(ch, line->len - (ch - line->s));
			/* multipart/(*) without boundary is invalid */
			if (ch == line->s + line->len)
				return -1;
			i = mime_param(ch, line->len - (ch - line->s));
			if (i >= 10) {
				if (!strncasecmp("boundary=", ch, 9)) {
					boundary->s = ch + 9;
					int quoted;
					if (*(ch + 9) == '"') {
						const char *e;

						quoted = 1;
						(boundary->s)++;
						e = memchr(ch + 10, '"', line->len - 10 - (ch - line->s));
						/* error would have been detected in mime_param() above */
						assert(e != NULL);
						j = e - ch - 10;
					} else {
						quoted = 0;
						j = 0;
						while (!WSPACE(boundary->s[j]) && (boundary->s[j] != ';') &&
										(boundary->s + j < line->s + line ->len)) {
							j++;
						}
					}
					boundary->len = j;

					if (!boundary->len) {
						write_status("D5.6.3 boundary definition is empty");
						net_conn_shutdown(shutdown_abort);
					} else if (boundary->len > 70) {
						write_status("D5.6.3 boundary definition is too long");
						net_conn_shutdown(shutdown_abort);
					} else if ((quoted == 1) && (boundary->s[boundary->len - 1] == ' ')) {
						write_status("D5.6.3 quoted boundary definition may not end in space");
						net_conn_shutdown(shutdown_abort);
					}

					while (j > 0) {
						j--;

						/* ascii letters are allowed */
						if (((boundary->s[j] >= 'a') && (boundary->s[j] <= 'z')) ||
								((boundary->s[j] >= 'A') && (boundary->s[j] <= 'Z')))
							continue;

						/* spaces are allowed inside quoted strings */
						if ((quoted == 1) && (boundary->s[j] == ' '))
							continue;

						/* more allowed chars, defined in RfC 2046, section 5.1.1. */
							/* +,-./0123456789: */
						if ((boundary->s[j] >= '+') && (boundary->s[j] <= ':'))
							continue;

						switch (boundary->s[j]) {
						case '\'':
						case '(':
						case ')':
						case '_':
						case '=':
						case '?':
							continue;
						default:
							write_status("D5.6.3 boundary definition contains invalid character");
							net_conn_shutdown(shutdown_abort);
						}
					}
					/* we have a valid boundary definition, that's all what we're interested in */
					return 1;
				}
			}
			if (!i)
				return -1;
			if (*(ch + i) == ';')
				i++;
		}
		return -1;
	}

	return 0;
}

/**
 * get length of a MIME header field, even if it is folded
 *
 * @param msg message data to scan
 * @param len length of data
 * @return length of header field
 * @retval 0 if field does not end until end of data
 */
size_t
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

/**
 * find next mime boundary
 *
 * @param buf buffer to scan
 * @param len length of buffer
 * @param boundary boundary limit string
 * @return offset of first character behind next boundary
 * @retval 0 no boundary found
 */
off_t
find_boundary(const char *buf, const off_t len, const cstring *boundary)
{
	off_t pos = 0;

	if (len < (off_t) (boundary->len + 3))
		return 0;
	while (pos <= len - 3 - (off_t) boundary->len) {
		if (((buf[pos] == '\r') || (buf[pos] == '\n')) && (buf[pos + 1] == '-') && (buf[pos + 2] == '-')) {
			if (!strncmp(buf + pos + 3, boundary->s, boundary->len)) {
				pos += 3 + boundary->len;
				if ((pos == len) || WSPACE(buf[pos]))
					return pos;
				if (pos + 1 < len) {
					if ((buf[pos] == '-') && (buf[pos + 1] == '-') &&
							((pos + 2 == len) || (WSPACE(buf[pos + 2])))) {
						return pos;
					}
				}
			}
		}
		pos++;
	}
	return 0;
}
