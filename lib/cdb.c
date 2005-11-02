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
cdb_hash(const unsigned char *buf, unsigned int len)
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

char *
cdb_seekmm(int fd, char *key, unsigned int len, char **mm, struct stat *st)
{
	char packbuf[8];
	uint32_t pos;
	uint32_t h;
	uint32_t lenhash;
	uint32_t h2;
	uint32_t loop;
	uint32_t poskd;
	char *cur;
	int err;

	*mm = mmap(NULL, st->st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (*mm == MAP_FAILED) {
		int e = errno;

		while (close(fd) && (errno == EINTR));
		errno = e;
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

		if (cdb_unpack(packbuf) == h) {
			cur = *mm + poskd;

			if (cdb_unpack(cur) == len)
				if (!strncmp(cur + 8, key, len))
					return cur + 8;
		}
		if (++h2 == lenhash)
			h2 = 0;
	}
out:
	err = errno;
	munmap(*mm, st->st_size);
	while (close(fd) && (errno == EINTR));
	errno = err;
	return NULL;
}
