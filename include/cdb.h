/** \file cdb.h
 \brief headers of function to read from CDB database
 */
#ifndef CDB_H
#define CDB_H

#include <sys/stat.h>

extern const char *cdb_seekmm(int, const char *, unsigned int, char **, const struct stat *);

#endif
