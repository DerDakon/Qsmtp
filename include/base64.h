#ifndef BASE64_H
#define BASE64_H

#include "sstring.h"

extern int b64decode(const unsigned char *, int, string *);
extern int b64encode(string *, string *);

#endif
