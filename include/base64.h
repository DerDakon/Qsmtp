/** \file base64.h
 \brief headers of Base64 encode and decode functions
 */
#ifndef BASE64_H
#define BASE64_H

#include "sstring.h"

extern int b64decode(const unsigned char *, size_t, string *) __attribute__ ((nonnull (3)));
extern int b64encode(string *, string *) __attribute__ ((nonnull (1,2)));

#endif
