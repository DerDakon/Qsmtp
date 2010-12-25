/** \file base64.h
 \brief headers of Base64 encode and decode functions
 */
#ifndef BASE64_H
#define BASE64_H

#include "sstring.h"

extern int b64decode(const char *in, size_t l, string *out) __attribute__ ((nonnull (3)));
extern int b64encode(const string *in, string *out) __attribute__ ((nonnull (1,2)));

#endif
