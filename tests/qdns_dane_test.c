#include <qdns_dane.h>

#include <qdns.h>

#include <assert.h>
#include <dns.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct dns_transmit dns_resolve_tx;
static int err;

static char **passed_q;
static struct {
	const char *packet;
	size_t len;
	int ret;
} patterns[] = {
	/* too short packet */
	{
		.packet = "\0",
		.len = 1,
		.ret = -EINVAL
	},
	/* correct header length, no name */
	{
		.packet = "\0\0\0\0\0\0\0\0\0\0\0\0",
		.len = 12,
		.ret = -ENOTBLK
	},
	/* answers = 0 -> no entries */
	{
		.packet = "\0\0\0\0\0\0\0\0\0\0\0\0\42",
		.len = 13,
		.ret = 0
	},
	/* answers = 65535, but packet too short for any data */
	{
		.packet = "\0\0\0\0\0\0\xff\xff\0\0\0\0\42",
		.len = 13,
		.ret = -ENOTBLK
	},
	/* answers = 65535, but packet too short for subheader */
	{
		.packet = "\0\0\0\0\0\0\xff\xff\0\0\0\0\42\0\0\0\0\42\0",
		.len = 19,
		.ret = -EINVAL
	},
	/* answers = 1, one subpacket of data length 0, wrong type, wrong class */
	{
		.packet = "\0\0\0\0\0\0\0\1\0\0\0\0" /* header */
			"\42" /* first name */
			"\0\0\0\0" /* 4 more */
			"\42" /*name of subrecord */
			"\0\0\0\0\0\0\0\0\0\0", /* subheader */
		.len = 28,
		.ret = 0
	},
	/* answers = 1, one subpacket of data length 0, correct type, wrong class */
	{
		.packet = "\0\0\0\0\0\0\0\1\0\0\0\0" /* header */
			"\42" /* first name */
			"\0\0\0\0" /* 4 more */
			"\42" /*name of subrecord */
			"\0\64\0\0\0\0\0\0\0\0", /* subheader */
		.len = 28,
		.ret = 0
	},
	/* answers = 1, one subpacket of data length 0, correct type, correct class */
	{
		.packet = "\0\0\0\0\0\0\0\1\0\0\0\0" /* header */
			"\42" /* first name */
			"\0\0\0\0" /* 4 more */
			"\42" /*name of subrecord */
			"\0\64\0\1\0\0\0\0\0\0", /* subheader */
		.len = 28,
		.ret = -EINVAL
	},
	/* answers = 1, one subpacket of data length 65535, correct type, correct class */
	{
		.packet = "\0\0\0\0\0\0\0\1\0\0\0\0" /* header */
			"\42" /* first name */
			"\0\0\0\0" /* 4 more */
			"\42" /*name of subrecord */
			"\0\64\0\1\0\0\0\0\xff\xff", /* subheader */
		.len = 28,
		.ret = -EINVAL
	},
	/* answers = 1, one subpacket of data length 3, correct type, correct class */
	{
		.packet = "\0\0\0\0\0\0\0\1\0\0\0\0" /* header */
			"\42" /* first name */
			"\0\0\0\0" /* 4 more */
			"\42" /*name of subrecord */
			"\0\64\0\1\0\0\0\0\0\3", /* subheader */
		.len = 28,
		.ret = -EINVAL
	},
	/* answers = 1, one subpacket of data length 4, correct type, correct class */
	/* matching type says SHA2-256, for which the length is too small */
	{
		.packet = "\0\0\0\0\0\0\0\1\0\0\0\0" /* header */
			"\42" /* first name */
			"\0\0\0\0" /* 4 more */
			"\42" /*name of subrecord */
			"\0\64\0\1\0\0\0\0\0\4" /* subheader */
			"\1\1\1" /* TLSA header */
			"\0", /* TLSA data */
		.len = 32,
		.ret = -EINVAL
	},
	/* answers = 1, one subpacket of data length 36 */
	/* matching type says SHA2-256, for which the length is too large */
	{
		.packet = "\0\0\0\0\0\0\0\1\0\0\0\0" /* header */
			"\42" /* first name */
			"\0\0\0\0" /* 4 more */
			"\42" /*name of subrecord */
			"\0\64\0\1\0\0\0\0\0\44" /* subheader */
			"\1\1\1" /* TLSA header */
			"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", /* TLSA data */
		.len = 67,
		.ret = -EINVAL
	},
	/* answers = 2, one valid SHA-256 packet, one of length 4 (invalid) */
	{
		.packet = "\0\0\0\0\0\0\0\2\0\0\0\0" /* header */
			"\42" /* first name */
			"\0\0\0\0" /* 4 more */
			"\42" /*name of subrecord */
			"\0\64\0\1\0\0\0\0\0\43" /* subheader */
			"\1\1\1" /* TLSA header */
			"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" /* TLSA data */
			"\42" /*name of subrecord */
			"\0\64\0\1\0\0\0\0\0\3" /* subheader */
			"\1\1\1", /* TLSA header */
		.len = 80,
		.ret = -EINVAL
	},
	/* answers = 3, one valid "full" packet, one valid SHA2-512 packet, third subrecord missing */
	{
		.packet = "\0\0\0\0\0\0\0\3\0\0\0\0" /* header */
			"\42" /* first name */
			"\0\0\0\0" /* 4 more */
			"\42" /*name of subrecord */
			"\0\64\0\1\0\0\0\0\0\4" /* subheader */
			"\2\1\0" /* TLSA header */
			"\0" /* TLSA data */
			"\42" /*name of subrecord */
			"\0\64\0\1\0\0\0\0\0\103" /* subheader */
			"\1\1\2" /* TLSA header */
			"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", /* TLSA data */
		.len = 110,
		.ret = -ENOTBLK
	}
};

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

static const char success_packet[] = "\0\0\0\0\0\0\0\3\0\0\0\0" /* header */
		"\42" /* first name */
		"\0\0\0\0" /* 4 more */
		"\42" /*name of subrecord */
		"\0\64\0\1\0\0\0\0\0\7" /* subheader */
		"\2\0\0" /* TLSA header */
		"\xf0\xf1\xf2\xf3" /* TLSA data */
		"\42" /*name of subrecord */
		"\0\64\0\1\0\0\0\0\0\103" /* subheader */
		"\1\1\2" /* TLSA header */
		"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
		"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
		"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
		"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf" /* TLSA data (SHA2-512) */
		"\42" /*name of subrecord */
		"\0\64\0\1\0\0\0\0\0\43" /* subheader */
		"\0\0\1" /* TLSA header */
		"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
		"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"; /* TLSA data (SHA2-512) */

// the API changed between libowfat 0.29 and 0.30
int
#if LIBOWFAT_UINT_DNSDOMFD == 0
dns_domain_fromdot(char **q, const char *host, size_t len)
#else
dns_domain_fromdot(char **q, const char *host, unsigned int len)
#endif
{

	if (len != strlen(host))
		err++;

	assert(len > 3);

	passed_q = q;

	if (strcmp(host, "_587._tcp.foo.example.com") == 0) {
		dns_resolve_tx.packet = (char *)success_packet;
		dns_resolve_tx.packetlen = sizeof(success_packet);
		return 1;
	}

	if (strcmp(host + 3, "._tcp.foo.example.org") != 0) {
		err++;
		return 0;
	}

	if (host[0] != '_') {
		err++;
		return 0;
	}

	if ((host[1] < '1') || (host[1] > '9') || (host[2] < '0') || (host[2] > '9')) {
		err++;
		return 0;
	}

	unsigned int idx = (host[1] - '1') * 10 + (host[2] - '0');

	if (idx < ARRAY_SIZE(patterns)) {
		dns_resolve_tx.packet = (char *)patterns[idx].packet;
		dns_resolve_tx.packetlen = patterns[idx].len;
	} else {
		dns_resolve_tx.packetlen = 0;
		if ((idx % 2) == 0)
			return 0;
	}

	return 1;
}

unsigned int
dns_packet_skipname(const char *buf, unsigned int len, unsigned int pos)
{
	if (len > pos) {
		if (buf[pos] != '\42') {
			errno = EFAULT;
			return 0;
		}
		return pos + 1;
	}

	/* this error code is junk, but is can easily be detected that
	 * this was the reason that the call failed */
	errno = ENOTBLK;
	return 0;
}

int
dns_resolve(const char *q, const char *type)
{
	assert(type != 0);
	assert(type[0] == 0);
	assert(type[1] == 52);
	assert(q == *passed_q);

	if (dns_resolve_tx.packetlen == 0) {
		errno = ENOMEM;
		return -1;
	} else {
		return 0;
	}
}

void
dns_domain_free(char **q)
{
	assert(*q == *passed_q);
}

void
dns_transmit_free(struct dns_transmit *t)
{
	assert(t == &dns_resolve_tx);
}

static int
test_success(void)
{
	struct daneinfo *val = NULL;
	int ret = 0;

	int r = dnstlsa("foo.example.com", 587, &val);
	int s = dnstlsa("foo.example.com", 587, NULL);

	if (r != s) {
		fprintf(stderr, "dnstlsa(foo.example.com, 587, NULL) returned %i, with pointer it returned %i\n",
				s, r);
		ret++;
	}

	if (r != 3) {
		fprintf(stderr, "dnstlsa(foo.example.com, 587, &val) returned %i, but 3 was expected\n",
				r);
		ret++;
		if (r > 3)
			r = 3;
	}

	for (s = 0; s < r; s++) {
		unsigned char v;
		size_t elen;
		size_t pos;

		switch (s) {
		case 0:
			v = '\xf0';
			elen = 4;
			break;
		case 1:
			v = '\x70';
			elen = 64;
			break;
		case 2:
			v = '\x30';
			elen = 32;
			break;
		}

		if (val[s].cert_usage != 2 - s) {
			fprintf(stderr, "%s: val[%i].cert_usage is %u, but %u was expected\n",
					__func__, s, val[s].cert_usage, s);
			ret++;
		}

		if (elen != val[s].datalen) {
			fprintf(stderr, "%s: val[%i].datalen is %zu, but %zu was expected\n",
					__func__, s, val[s].datalen, elen);
			ret++;
		}

		for (pos = 0; pos < val[s].datalen; pos++, v++)
			if (val[s].data[pos] != v) {
				fprintf(stderr, "%s: val[%i].data[%zu] is 0x%02x, but 0x%02x was expected\n",
						__func__, s, pos, val[s].data[pos], v);
				ret++;
				break;
			}

		free(val[s].data);
	}

	free(val);

	return ret;
}

int
main(void)
{
	struct daneinfo *val = (struct daneinfo *)(uintptr_t)-1;

	for (unsigned short i = 98; i <= 99; i++) {
		if (dnstlsa("foo.example.org", i, NULL) != DNS_ERROR_LOCAL)
			err++;

		if (dnstlsa("foo.example.org", i, &val) != DNS_ERROR_LOCAL)
			err++;

		if (val != NULL)
			err++;
	}

	errno = 0;
	for (unsigned short i = 0; i < ARRAY_SIZE(patterns); i++) {
		const int s = dnstlsa("foo.example.org", i + 10, NULL);
		const int r = dnstlsa("foo.example.org", i + 10, &val);

		if (r != s) {
			fprintf(stderr, "dnstlsa(x, %u, NULL) returned %i, but dnstlsa(x, %u, &val) returned %i\n",
					i + 10, s, i + 10, r);
			err++;
		}

		if (patterns[i].ret < 0) {
			if ((r != DNS_ERROR_LOCAL) || (errno != -patterns[i].ret)) {
				fprintf(stderr, "dnstlsa(x, %u, ...) returned %i/%i, but expected was %i/%i\n",
						i + 10, r, errno, DNS_ERROR_LOCAL, -patterns[i].ret);
				err++;
			}
		} else {
			if (r != patterns[i].ret) {
				fprintf(stderr, "dnstlsa(x, %u, ...) returned %i/%i, but expected was %i\n",
						i +  10, r, errno, patterns[i].ret);
				err++;
			}
		}

		if (r > 0) {
			int j;

			for (j = 0; j < r; j++)
				free(val[j].data);
			free(val);
		}
		errno = 0;
	}

	err += test_success();

	return err;
}
