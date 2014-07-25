#define WRITE_SIDE
#include "netio_test_messages.h"

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int
main(void)
{
	unsigned int i = 0;

	while (write_chunks[i] != NULL) {
		size_t slen = strlen(write_chunks[i]);
		size_t wlen = write(1, write_chunks[i], slen);

		assert(slen == wlen);

		usleep(200000);
		i++;
	}

	close(1);

	return 0;
}
