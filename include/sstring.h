#ifndef SSTRING_H
#define SSTRING_H

#include <errno.h>
#include <stdlib.h>

typedef struct string {
	char *s;
	unsigned int len;
} string;

#define STREMPTY(x) {(x).s = NULL; (x).len = 0; }

static inline int
newstr(string *s, const unsigned int len)
{
	s->len = len;
	s->s = malloc(len);
	return (len && !s->s) ? -1 : 0;
}

#endif
