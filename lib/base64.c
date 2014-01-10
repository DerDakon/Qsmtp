/** \file base64.c
 \brief Base64 encoding and decoding functions
 */
#include "base64.h"
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "sstring.h"

static const char *b64alpha =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define B64PAD ((char) '=')

/**
 * decode base64 string to plain text
 *
 * @param in base64 text
 * @param l length of in
 * @param out string to store decoded string (memory will be malloced)
 * @retval <0 negative error code
 * @retval 0 on success
 * @retval 1 on parse error
 *
 * The contents of out are undefined as long as something else than 0 is
 * returned, i.e. the memory is freed but the freed pointer may still be
 * recorded in out.
 */
int
b64decode(const char *in, size_t l, string *out)
{
	size_t i, j;
	unsigned char a[4];
	unsigned char b[3];
	char *s;

	if (l == 0) {
		STREMPTY(*out);
		return 0;
	}

	assert(in != NULL);

	out->s = malloc(l + 3);
	if (!out->s)
		return -ENOMEM;

	s = out->s;

	for (i = 0; i < l; i += 4) {
		for (j = 0; j < 4; j++) {
			if (in[i + j] == '\r') {
				if (i + j + 1 == l) {
					free(out->s);
					return 1;
				}
				i++;
				if (in[i + j] != '\n') {
					free(out->s);
					return 1;
				}
				i++;
			}

			if (((i + j) < l) && (in[i + j] != B64PAD)) {
				char *c;

				c = strchr(b64alpha, in[i + j]);

				if (!c) {
					free(out->s);
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

		if ((i + 2 >= l) || (in[i + 2] == B64PAD))
			break;
		*s++ = b[1];

		if ((i + 3 >= l) || (in[i + 3] == B64PAD))
			break;
		*s++ = b[2];
	}
	out->len = s - out->s;
	*s = '\0';
	while (out->len && !out->s[out->len - 1])
		--out->len; /* XXX avoid? */
	return 0;
}

/**
 * encode plain text string to Base64
 *
 * @param in plain text string
 * @param out string to store Base64 string (memory will be malloced)
 * @param wraplimit the number of characters after which a CRLF pair should be inserted
 * @retval 0 on success
 * @retval <0 negative error code
 */
int
b64encode(const string *in, string *out, const unsigned int wraplimit)
{
	size_t i;
	char *s;
	unsigned int oline = 0;

	if (in->len == 0) {
		STREMPTY(*out);
		return 0;
	}

	/* how many output characters we need for the input stream */
	i = in->len / 3 * 4;
	/* add one CRLF every wraplimit characters and some space at the end for padding,
	 * a CRLF in padding and \0 */
	out->s = malloc(i + (i / wraplimit) * 2 + 7);
	if (!out->s)
		return -ENOMEM;

	s = out->s;

	for (i = 0; i < in->len; i += 3) {
		const unsigned char a = in->s[i];
		const unsigned char b = (i + 1 < in->len) ? in->s[i + 1] : 0;
		const unsigned char c = (i + 2 < in->len) ? in->s[i + 2] : 0;

		*s++ = b64alpha[a >> 2];
		*s++ = b64alpha[((a & 3 ) << 4) | (b >> 4)];
		oline += 2;

		if (i + 1 >= in->len)
			*s++ = B64PAD;
		else
			*s++ = b64alpha[((b & 15) << 2) | (c >> 6)];
		oline++;

		if (i + 2 >= in->len)
			*s++ = B64PAD;
		else
			*s++ = b64alpha[c & 63];

		if (++oline >= wraplimit) {
			const unsigned int shift = oline - wraplimit + 1;
			char movebuf[4];

			assert(sizeof(movebuf) >= shift);

			memcpy(movebuf, s - shift, shift);
			s -= shift;

			*s++ = '\r';
			*s++ = '\n';

			memcpy(s, movebuf, shift);
			s += shift;
			oline = shift;
		}
	}
	out->len = s - out->s;
	*s = '\0';

	return 0;
}
