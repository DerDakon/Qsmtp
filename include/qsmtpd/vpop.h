/** \file vpop.h
 \brief declaration of function for accessing vpopmail data files
 */
#ifndef VPOP_H
#define VPOP_H

struct userconf;

extern int vget_dir(const char *, struct userconf *) __attribute__ ((nonnull (1, 2)));

#endif
