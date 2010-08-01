/** \file cdb.c
 * \brief functions to read from CDB database
 */
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "cdb.h"

#define CDB_HASHSTART 5381

static inline uint32_t
cdb_hash(const char *buf, unsigned int len)
{
	uint32_t h;

	h = CDB_HASHSTART;
	while (len--) {
		h += (h << 5);
		h ^= (uint32_t) *buf++;
	}
	return h;
}

static inline uint32_t
cdb_unpack(const unsigned char *buf)
{
#ifdef __le32_to_cpup
	return __le32_to_cpup((uint32_t *) buf);
#else
	return (buf[3] << 24) + (buf[2] << 16) + (buf[1] << 8) + buf[0];
#endif
}

/**
 * perform cdb search on the given file
 *
 * @param fd file descriptor to search (will be closed)
 * @param key key to search for
 * @param len length of key
 * @param mm base of mmapped address space
 * @param st file information
 * @returns cdb value belonging to that key
 * @retval NULL no key found in database or error
 *
 * If the function returns NULL and errno is 0 everything worked fine
 * but there is no entry for key in the file. On error errno is set.
 *
 * The file is mmaped into memory, the result pointer will point inside that
 * memory. The caller must munmap() the value returned in mm if the function
 * does not return NULL. fd will be closed before the function returns.
 */
const char *
cdb_seekmm(int fd, const char *key, unsigned int len, char **mm, const struct stat *st)
{
	uint32_t pos;
	uint32_t h;
	uint32_t lenhash;
	uint32_t h2;
	uint32_t loop;
	uint32_t poskd;
	char *cur;
	int err;

	*mm = mmap(NULL, st->st_size, PROT_READ, MAP_SHARED, fd, 0);
	err = errno;
	
	while (close(fd) && (errno == EINTR));
	
	if (*mm == MAP_FAILED) {
		errno = err;
		return NULL;
	}

	errno = 0;
	h = cdb_hash(key, len);

	pos = 8 * (h & 255);

	lenhash = cdb_unpack(*mm + pos + 4);

	if (!lenhash)
		goto out;
	h2 = (h >> 8) % lenhash;

	pos = cdb_unpack(*mm + pos);

	for (loop = 0; loop < lenhash; ++loop) {
		cur = *mm + pos + 8 * h2;
		poskd = cdb_unpack(cur + 4);

		if (!poskd)
			break;

		if (cdb_unpack(cur) == h) {
			cur = *mm + poskd;

			if (cdb_unpack(cur) == len)
				if (!strncmp(cur + 8, key, len))
					return cur + 8 + len;
		}
		if (++h2 == lenhash)
			h2 = 0;
	}
out:
	err = errno;
	munmap(*mm, st->st_size);
	errno = err;
	return NULL;
}
