#include <stdlib.h>

#define CHUNK(x) "chunk" #x

#ifdef WRITE_SIDE

static const char *write_chunks[] = {
	/* one chunk a line */
	CHUNK(1) "\r\n",
	/* two lines sent at the same time */
	CHUNK(2) "\r\n" CHUNK(3) "\r\n",
	/* one line sent in 2 parts */
	CHUNK(4),
	CHUNK(5) "\r\n",
	/* one line sent in 2 parts, split at a weird position */
	CHUNK(6) "\r",
	"\n" CHUNK(7) "\r\n",
	/* another line, sent separated from CRLF */
	CHUNK(8),
	"\r",
	"\n",
	/* another version */
	CHUNK(9),
	"\r\n",
	/* end */
	NULL
};

#else

static const char *read_chunks[] = {
	CHUNK(1),
	CHUNK(2),
	CHUNK(3),
	CHUNK(4) CHUNK(5),
	CHUNK(6),
	CHUNK(7),
	CHUNK(8),
	CHUNK(9),
	NULL
};

#endif
