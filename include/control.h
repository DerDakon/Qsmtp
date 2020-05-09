/** \file control.h
 \brief headers of functions for control file handling
 */
#ifndef CONTROL_H
#define CONTROL_H

#include "compiler.h"

#include <sys/types.h>

/**
 * @brief callback to determine if a line in file is valid
 * @param line the 0-terminated string of the current line
 * @returns if the line is valid or not
 * @retval 0 the line is not valid and should be ignored
 */
typedef int (*checkfunc)(const char *line);

extern int controldir_fd;

extern size_t lloadfilefd(int, char **, const int striptab) __attribute__ ((nonnull (2)));
extern int loadintfd(int, unsigned long *, const unsigned long def) __attribute__ ((nonnull (2)));
extern size_t loadoneliner(int base, const char *filename, char **buf, const int optional) __attribute__ ((nonnull (2, 3)));
extern size_t loadonelinerfd(int fd, char **buf) __attribute__ ((nonnull (2)));
extern int loadlistfd(int, char ***, checkfunc) __attribute__ ((nonnull (2)));
extern int finddomainfd(int, const char *, const int) __attribute__ ((nonnull (2)));
extern int finddomain(const char *buf, const off_t size, const char *domain) __attribute__ ((nonnull (3))) ATTR_ACCESS(read_only, 1, 2);

extern char **data_array(unsigned int entries, size_t datalen, void *oldbuf, size_t oldlen) ATTR_ACCESS(read_write, 3, 4);

#endif
