#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"
#include "sstring.h"

static unsigned char *b64alpha =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define B64PAD ((unsigned char) '=')

/* returns 0 ok, >0 illegal, -1 problem */

int b64decode(const unsigned char *in, size_t l, string *out)
{
	size_t i, j;
	unsigned char a[4];
	unsigned char b[3];
	char *s;

	if (l == 0) {
		STREMPTY(*out);
		return 0;
	}

	out->s = malloc(l + 3);
	if (!out->s) {
		return -1;
	}
	s = out->s;

	for (i = 0; i < l; i += 4) {
		for (j = 0; j < 4; j++) {
			if (((i + j) < l) && (in[i + j] != B64PAD)) {
				unsigned char *c = strchr(b64alpha, in[i + j]);
		
				if (!c) {
					return 1;
				}
				a[j] = c - b64alpha;
			} else {
				a[j] = 0;
			}
		}

		b[0] = (a[0] << 2) | (a[1] >> 4);
		b[1] = (a[1] << 4) | (a[2] >> 2);
		b[2] = (a[2] << 6) | (a[3]);

		*s++ = b[0];

		if (in[i + 1] == B64PAD)
			break;
		*s++ = b[1];

		if (in[i + 2] == B64PAD)
			break;
		*s++ = b[2];
	}
	out->len = s - out->s;
	*s = '\0';
	while (out->len && !out->s[out->len - 1])
		--out->len; /* XXX avoid? */
	return 0;
}

int b64encode(string *in, string *out)
{
	unsigned char a, b, c;
	size_t i;
	char *s;

	if (in->len == 0) {
		STREMPTY(*in);
		return 0;
	}

	out->s = malloc(in->len / 3 * 4 + 5);
	if (!out->s) {
		return -1;
	}
	s = out->s;

	for (i = 0; i < in->len; i += 3) {
		a = in->s[i];
		b = (i + 1 < in->len) ? in->s[i + 1] : 0;
		c = (i + 2 < in->len) ? in->s[i + 2] : 0;

		*s++ = b64alpha[a >> 2];
		*s++ = b64alpha[((a & 3 ) << 4) | (b >> 4)];

		if (i + 1 >= in->len)
			*s++ = B64PAD;
		else
			*s++ = b64alpha[((b & 15) << 2) | (c >> 6)];

		if (i + 2 >= in->len)
			*s++ = B64PAD;
		else
			*s++ = b64alpha[c & 63];
	}
	out->len = s - out->s;
	*s = '\0';

	return 0;
}
