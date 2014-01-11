/** \file base64_test.c
 \brief BASE64 testcases
 */

#include "base64.h"
#include "sstring.h"
#include "test_io/testcase_io.h"

#include <stdio.h>
#include <string.h>

static int
check_line_limit(const string *bdata, const unsigned int maxlinelen)
{
	const char *lstart, *lend;

	/* verify that the lines are wrapped at the given limit */
	lend = bdata->s;
	do {
		lstart = lend;
		lend = strstr(lstart, "\r\n");
		
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
	string outdata;	/**< output pattern after encoding and decoding */
	string bdata;	/**< intermediate base64 pattern */
	size_t l;
	unsigned int pattern;

	puts("== Testing if encode and decode are reverse operations");

	if (newstr(&indata, 512) != 0) {
		puts("Error: not enough memory to run test");
		return 1;
	}

	for (pattern = 0; pattern <= 1; pattern++) {
		unsigned int maxlinelen = (1 + pattern) * 40;

		switch (pattern) {
		case 0:
			for (l = 0; l < indata.len; l++) {
				indata.s[l] = (unsigned char)(l & 0xff);
			}
			break;
		case 1:
			for (l = 0; l < indata.len / 2; l++) {
				indata.s[l] = (unsigned char)(l & 0xff);
			}
			for (l = indata.len / 2; l < indata.len; l++) {
				indata.s[l] = 0xff - (unsigned char)(l & 0xff);
			}
			break;
		default:
			return 2;
		}

		if (b64encode(&indata, &bdata, maxlinelen) != 0) {
			puts("Error: encoding failed");
			return 1;
		}

		if (check_line_limit(&bdata, maxlinelen))
			return 1;

		if (b64decode(bdata.s, bdata.len, &outdata) != 0) {
			puts("Error: decoding failed");
			return 1;
		}

		/* a trayling '\0' may be lost in the encoding due to padding bytes */
		if ((indata.s[indata.len - 1] == '\0') && (outdata.len == indata.len - 1)) {
			indata.len --;
		}

		if (outdata.len != indata.len) {
			puts("Error: outdata and indata have different length");
			return 1;
		}

		for (l = 0; l < outdata.len; l++) {
			if (indata.s[l] != outdata.s[l]) {
				puts("Error: input and output do not match");
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
	string outdata;	/**< output pattern after encoding and decoding */
	string bdata;	/**< intermediate base64 pattern */
	char *base;
	const size_t maxlen = 512;
	size_t l;

	puts("== Testing if encode and decode are reverse operations for different pattern lengths");

	if (newstr(&indata, maxlen) != 0) {
		puts("Error: not enough memory to run test");
		return 1;
	}

	base = indata.s;

	for (l = 0; l < indata.len; l++)
		indata.s[l] = (unsigned char)(l & 0xff);

	for (l = 0; l < maxlen; l++) {
		unsigned int maxlinelen;

		indata.s = base + l;
		indata.len = maxlen - l;

		for (maxlinelen = 70; maxlinelen <= 80; maxlinelen++) {
			size_t k;
			char *tmp;

			if (b64encode(&indata, &bdata, maxlinelen) != 0) {
				puts("Error: encoding failed");
				return 1;
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
				puts("Error: outdata and indata have different length");
				return 1;
			}

			for (k = 0; k < outdata.len; k++) {
				if (indata.s[k] != outdata.s[k]) {
					puts("Error: input and output do not match");
					return 1;
				}
			}

			free(outdata.s);
			free(bdata.s);
		}
	}

	free(base);

	return 0;
}

static int
iface_test(void)
{
	string indata;
	string outdata;
	const char junk = 'j';
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

	if (b64decode(&junk, 0, &outdata) != 0) {
		puts("Error: decoding empty junk string failed");
		err++;
	}
	if ((outdata.len != 0) || (outdata.s != NULL)) {
		puts("Error: output of decoding empty junk string is not empty");
		err++;
	}

	STREMPTY(indata);

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
	unsigned char i;
	static const char badchars[] = "\"'\r\n,.-;:_#!$%&()";
	string odata;
	int r;

	for (i = 'A'; i <= 'Z'; i++)
		testpattern[pos++] = i;
	for (i = 'a'; i <= 'z'; i++)
		testpattern[pos++] = i;
	for (i = '0'; i <= '9'; i++)
		testpattern[pos++] = i;
	testpattern[pos++] = '+';
	testpattern[pos++] = '/';
	while (pos < sizeof(testpattern) - 1)
		testpattern[pos++] = '=';
	testpattern[pos] = '\0';

	puts("== Running error detection test");

	for (i = 0; i < strlen(testpattern); i++) {
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

	for (i = 0; i < strlen(badchars); i++) {
		STREMPTY(odata);
		memcpy(testdata, testpattern, sizeof(testpattern));
		testdata[42] = badchars[i];
		b64decode(testdata, sizeof(testdata) - 1, &odata);
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
