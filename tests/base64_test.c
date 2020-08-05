/** \file base64_test.c
 \brief BASE64 testcases
 */

#include <base64.h>
#include <sstring.h>
#include "test_io/testcase_io.h"

#include <stdio.h>
#include <string.h>

/**
 * @brief find a string in a given memory area
 *
 * memmem() is a GNU extension, so implement it on our own. Since this
 * is only used to find line endings hardcode that.
 */
static const char *
memcrlf(const char *start, const size_t maxlen)
{
	const char *res = memchr(start, '\r', maxlen - 1);

	while (res != NULL) {
		if (*(res + 1) == '\n')
			break;

		res = memchr(res + 1, '\r', maxlen - 1 - (res - start));
	}

	return res;
}

static int
check_line_limit(const string *bdata, const unsigned int maxlinelen)
{
	/* verify that the lines are wrapped at the given limit */
	const char *lend = bdata->s;
	do {
		const char *lstart = lend;
		lend = memcrlf(lstart, bdata->len - (lstart - bdata->s));

		if (lend == NULL) {
			const size_t foundlen = bdata->s + bdata->len - lstart;
			if (foundlen > maxlinelen) {
				fprintf(stderr, "last part has a len of %zu, but a maximum of %u was expected\n",
					foundlen, maxlinelen);
				return 1;
			}
			break;
		} else {
			if (lend - lstart > maxlinelen) {
				fprintf(stderr, "part at offset %zu has a len of %zu, but a maximum of %u was expected\n",
					lstart - bdata->s, lend - lstart, maxlinelen);
				return 1;
			}

			lend += 2;
		}
	} while ((lend < bdata->s + bdata->len) && (*lend != '\0'));

	return 0;
}

static int
inout_test(void)
{
	string indata;	/**< input pattern */

	puts("== Testing if encode and decode are reverse operations");

	if (newstr(&indata, 512) != 0) {
		puts("Error: not enough memory to run test");
		return 1;
	}

	for (unsigned int pattern = 0; pattern <= 1; pattern++) {
		unsigned int maxlinelen = (1 + pattern) * 40;

		switch (pattern) {
		case 0:
			for (size_t l = 0; l < indata.len; l++) {
				indata.s[l] = (unsigned char)(l & 0xff);
			}
			break;
		case 1:
			for (size_t l = 0; l < indata.len / 2; l++) {
				indata.s[l] = (unsigned char)(l & 0xff);
			}
			for (size_t l = indata.len / 2; l < indata.len; l++) {
				indata.s[l] = 0xff - (unsigned char)(l & 0xff);
			}
			break;
		default:
			return 2;
		}

		string bdata;	/**< intermediate base64 pattern */
		if (b64encode(&indata, &bdata, maxlinelen) != 0) {
			puts("Error: encoding failed");
			return 1;
		}

		if (check_line_limit(&bdata, maxlinelen)) {
			free(bdata.s);
			return 1;
		}

		string outdata;	/**< output pattern after encoding and decoding */
		if (b64decode(bdata.s, bdata.len, &outdata) != 0) {
			puts("Error: decoding failed");
			free(bdata.s);
			return 1;
		}

		/* a trayling '\0' may be lost in the encoding due to padding bytes */
		if ((indata.s[indata.len - 1] == '\0') && (outdata.len == indata.len - 1)) {
			indata.len --;
		}

		if (outdata.len != indata.len) {
			puts("Error: outdata and indata have different length");
			free(outdata.s);
			return 1;
		}

		for (size_t l = 0; l < outdata.len; l++) {
			if (indata.s[l] != outdata.s[l]) {
				puts("Error: input and output do not match");
				free(outdata.s);
				free(indata.s);
				return 1;
			}
		}

		free(outdata.s);
		free(bdata.s);
	}

	free(indata.s);

	return 0;
}

static int
padding_test(void)
{
	string indata;	/**< input pattern */
	const size_t maxlen = 512;
	int ret = 0;

	puts("== Testing if encode and decode are reverse operations for different pattern lengths");

	if (newstr(&indata, maxlen) != 0) {
		puts("Error: not enough memory to run test");
		return 1;
	}

	char *base = indata.s;

	for (size_t l = 1; l < maxlen; l++) {
		unsigned int maxlinelen;
		string outdata;	/**< output pattern after encoding and decoding */
		string bdata;	/**< intermediate base64 pattern */

		indata.s = base + l;
		indata.len = maxlen - l;
		for (size_t k = 0; k < indata.len; k++)
			indata.s[k] = (unsigned char)((k + 1) & 0xff);

		for (maxlinelen = 70; maxlinelen <= 80; maxlinelen++) {
			char *tmp;

			if (b64encode(&indata, &bdata, maxlinelen) != 0) {
				printf("Error: encoding failed, length %zu, line length %u",
						l, maxlinelen);
				ret++;
				continue;
			}

			if (check_line_limit(&bdata, maxlinelen))
				return 1;

			tmp = realloc(bdata.s, bdata.len);
			if (tmp == NULL) {
				printf("realloc() failed to truncate\n");
				free(bdata.s);
				return 1;
			}
			bdata.s = tmp;

			if (b64decode(bdata.s, bdata.len, &outdata) != 0) {
				printf("Error: decoding failed, maxlinelen = %u, l = %zu\n", maxlinelen, l);
				return 1;
			}

			/* a trayling '\0' may be lost in the encoding due to padding bytes */
			if ((indata.s[indata.len - 1] == '\0') && (outdata.len == indata.len - 1)) {
				indata.len --;
			}

			if (outdata.len != indata.len) {
				printf("Error: outdata (%zu) and indata (%zu) have different length\n",
						outdata.len, indata.len);
				ret++;
				free(outdata.s);
				continue;
			}

			for (size_t k = 0; k < outdata.len; k++) {
				if (indata.s[k] != outdata.s[k]) {
					printf("Error: input and output do not match at position %zu\n", k);
					return ++ret;
				}
			}

			free(outdata.s);

			/* add CRLF pair to catch overrun when line endings are skipped */
			if (bdata.s[bdata.len - 1] != '\n') {
				tmp = realloc(bdata.s, bdata.len + 2);
				if (tmp == NULL) {
					puts("Error: could not add 2 byte to Base64 data\n");
					free(bdata.s);
					return ++ret;
				}

				bdata.s = tmp;
				tmp[bdata.len++] = '\r';
				tmp[bdata.len++] = '\n';

				if (b64decode(bdata.s, bdata.len, &outdata) != 0) {
					printf("Error: decoding failed, maxlinelen = %u, l = %zu\n", maxlinelen, l);
					ret++;
					free(bdata.s);
					continue;
				}

				free(bdata.s);

				if (outdata.len != indata.len) {
					printf("Error: outdata (%zu) and indata (%zu) have different length with CRLF ending\n",
							outdata.len, indata.len);
					ret++;
					free(outdata.s);
					continue;
				}

				for (size_t k = 0; k < outdata.len; k++) {
					if (indata.s[k] != outdata.s[k]) {
						printf("Error: input and output do not match at position %zu\n", k);
						return ++ret;
					}
				}

				free(outdata.s);
			} else {
				free(bdata.s);
			}
		}
	}

	free(base);

	return ret;
}

static int
iface_test(void)
{
	
	string outdata;
	int err = 0;

	puts("== Running base64 interface tests");

	if (b64decode(NULL, 0, &outdata) != 0) {
		puts("Error: decoding NULL string failed");
		err++;
	}
	if ((outdata.len != 0) || (outdata.s != NULL)) {
		puts("Error: output of decoding NULL string is not empty");
		err++;
	}

	if (b64decode(NULL, 0, &outdata) != 0) {
		puts("Error: decoding empty junk string failed");
		err++;
	}
	if ((outdata.len != 0) || (outdata.s != NULL)) {
		puts("Error: output of decoding empty junk string is not empty");
		err++;
	}

	string indata = STREMPTY_INIT;

	if (b64encode(&indata, &outdata, 42) != 0) {
		puts("Error: encoding empty string failed");
		err++;
	}
	if ((outdata.len != 0) || (outdata.s != NULL)) {
		puts("Error: output of encoding empty string is not empty");
		err++;
	}

	return err;
}

static int
errdetect_test(void)
{
	char testpattern[68];
	char testdata[sizeof(testpattern)];
	unsigned int pos = 0;
	static const char badchars[] = "\"'\r\n,.-;:_#!$%&()";
	string odata;
	int r;

	for (unsigned char i = 'A'; i <= 'Z'; i++)
		testpattern[pos++] = i;
	for (unsigned char i = 'a'; i <= 'z'; i++)
		testpattern[pos++] = i;
	for (unsigned char i = '0'; i <= '9'; i++)
		testpattern[pos++] = i;
	testpattern[pos++] = '+';
	testpattern[pos++] = '/';
	while (pos < sizeof(testpattern) - 1)
		testpattern[pos++] = '=';
	testpattern[pos] = '\0';

	puts("== Running error detection test");

	for (size_t i = 0; i < strlen(testpattern); i++) {
		STREMPTY(odata);
		memcpy(testdata, testpattern, sizeof(testpattern));
		testdata[i] += 128;
		r = b64decode(testdata, sizeof(testdata) - 1, &odata);
		if (r == 0)
			free(odata.s);
		if (r <= 0) {
			puts("Error: invalid input stream is not rejected");
			return 1;
		}
	}

	for (size_t i = 0; i < strlen(badchars); i++) {
		STREMPTY(odata);
		memcpy(testdata, testpattern, sizeof(testpattern));
		testdata[42] = badchars[i];
		r = b64decode(testdata, sizeof(testdata) - 1, &odata);
		if (r == 0)
			free(odata.s);
		if (r <= 0) {
			puts("Error: invalid input stream is not rejected");
			return 1;
		}
	}

	STREMPTY(odata);
	/* testing a string that ends in \r */
	memcpy(testdata, testpattern, 16);
	testdata[17] = '\r';
	testdata[18] = '\0';

	r = b64decode(testdata, 18, &odata);
	if (r == 0)
		free(odata.s);
	if (r <= 0) {
		puts("Error: invalid input stream ending in CR is not rejected");
		return 1;
	}

	return 0;
}

int
main(void)
{
	int errcnt = 0;

	if (iface_test())
		errcnt++;

	if (inout_test())
		errcnt++;

	if (errdetect_test())
		errcnt++;

	if (padding_test())
		errcnt++;

	return (errcnt != 0) ? 1 : 0;
}
