#ifndef MMAP_H
#define MMAP_H

#include <sys/types.h>

extern void *mmap_fd(int fd, off_t *len);
extern void *mmap_name(const char *fname, off_t *len, int *fd);

#endif
