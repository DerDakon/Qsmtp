#ifndef BASE64_H
#define BASE64_H

#include "sstring.h"

extern int b64decode(const unsigned char *, size_t, string *);
extern int b64encode(string *, string *);

#endif
