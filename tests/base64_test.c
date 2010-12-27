/** \file base64_test.c
 \brief BASE64 testcases
 */

#include "base64.h"
#include "sstring.h"

#include <stdio.h>
#include <string.h>

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

		if (b64encode(&indata, &bdata) != 0) {
			puts("Error: encoding failed");
			return 1;
		}

		if (b64decode(bdata.s, bdata.len, &outdata) != 0) {
			puts("Error: decoding failed");
			return 1;
		}

		/* a trayling '\0' may be lost in the encoding due to padding bytes */
		if ((indata.s[indata.len - 1] == '\0') && (outdata.len == indata.len - 1)) {
			indata.len --;
		}

		if (outdata.len != indata.len) {
			if (indata.s[indata.len - 1] == '\0') {

			}
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
	size_t l;

	puts("== Testing if encode and decode are reverse operations for different pattern lengths");

	if (newstr(&indata, 512) != 0) {
		puts("Error: not enough memory to run test");
		return 1;
	}

	for (l = 1; l < 255; l++) {
		size_t k;
		for (k = 0; k < l; k++) {
			indata.s[k] = (unsigned char)(k & 0xff);
		}
		indata.s[l] = '\0';
		indata.len = l;

		if (b64encode(&indata, &bdata) != 0) {
			puts("Error: encoding failed");
			return 1;
		}

		if (b64decode(bdata.s, bdata.len, &outdata) != 0) {
			puts("Error: decoding failed");
			return 1;
		}

		/* a trayling '\0' may be lost in the encoding due to padding bytes */
		if ((indata.s[indata.len - 1] == '\0') && (outdata.len == indata.len - 1)) {
			indata.len --;
		}

		if (outdata.len != indata.len) {
			if (indata.s[indata.len - 1] == '\0') {

			}
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

	free(indata.s);

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

	if (b64encode(&indata, &outdata) != 0) {
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
		if (b64decode(testdata, sizeof(testdata) - 1, &odata) <= 0) {
			puts("Error: invalid input stream is not rejected");
			return 1;
		}
		free(odata.s);
	}

	for (i = 0; i < strlen(badchars); i++) {
		STREMPTY(odata);
		memcpy(testdata, testpattern, sizeof(testpattern));
		testdata[42] = badchars[i];
		if (b64decode(testdata, sizeof(testdata) - 1, &odata) <= 0) {
			puts("Error: invalid input stream is not rejected");
			return 1;
		}
		free(odata.s);
	}

	STREMPTY(odata);
	/* testing a string that ends in \r */
	memcpy(testdata, testpattern, 16);
	testdata[17] = '\r';
	testdata[18] = '\0';

	if (b64decode(testdata, 18, &odata) <= 0) {
		puts("Error: invalid input stream ending in CR is not rejected");
		return 1;
	}
	free(odata.s);

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
