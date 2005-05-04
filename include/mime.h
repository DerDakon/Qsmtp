#ifndef MIME_H
#define MIME_H

#include <sys/types.h>
#include "sstring.h"

extern const char * __attribute__ ((pure)) skipwhitespace(const char *line, const size_t len);
extern int __attribute__ ((pure)) is_multipart(const cstring *);
extern size_t __attribute__ ((pure)) getfieldlen(const char *, const size_t);
extern size_t __attribute__ ((pure)) mime_param(const char *, const size_t);
extern size_t __attribute__ ((pure)) mime_token(const char *, const size_t);

#define TSPECIAL(a) (((a) == '(') || ((a) == ')') || ((a) == '<') || ((a) == '>') || ((a) == '@') || \
			((a) == ',') || ((a) == ';') || ((a) == ':') || ((a) == '\\') || ((a) == '"') || \
			((a) == '/') || ((a) == '[') || ((a) == ']') || ((a) == '?') || ((a) == '='))
#define WSPACE(a) (((a) == ' ') || ((a) == '\t') || ((a) == '\r') || ((a) == '\n'))

#endif
