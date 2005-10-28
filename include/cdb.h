/** \file cdb.h
 \brief headers of function to read from CDB database
 */
#ifndef CDB_H
#define CDB_H

#include <sys/stat.h>

extern char *cdb_seekmm(int, char *, unsigned int, char **, struct stat *);

#endif
