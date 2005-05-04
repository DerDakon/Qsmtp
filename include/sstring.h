#ifndef SSTRING_H
#define SSTRING_H

#include <errno.h>
#include <stdlib.h>

typedef struct string {
	char *s;
	size_t len;
} string;

typedef struct cstring {
	const char *s;
	size_t len;
} cstring;

#define STREMPTY(x) {(x).s = NULL; (x).len = 0; }

static inline int
newstr(string *s, const size_t len)
{
	s->len = len;
	s->s = malloc(len);
	return (len && !s->s) ? -1 : 0;
}

#endif
