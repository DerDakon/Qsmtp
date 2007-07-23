#ifndef MMAP_H
#define MMAP_H

#include "qoff.h"

extern void *mmap_fd(int fd, q_off_t *len);
extern void *mmap_name(const char *fname, q_off_t *len, int *fd);

#endif
