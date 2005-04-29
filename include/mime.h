#ifndef MIME_H
#define MIME_H

#include <sys/types.h>
#include "sstring.h"

extern const char * __attribute__ ((pure)) skipwhitespace(const char *line, const size_t len);
extern int __attribute__ ((pure)) is_multipart(const struct string *);
extern size_t __attribute__ ((pure)) getfieldlen(const char *, const size_t);

#endif
