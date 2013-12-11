/** \file vpop.h
 \brief declaration of function for accessing vpopmail data files
 */
#ifndef VPOP_H
#define VPOP_H

#include "sstring.h"

extern int vget_dir(const char *, string *) __attribute__ ((nonnull (1, 2)));

extern int userbackend_init(void);
extern void userbackend_free(void);

#endif
