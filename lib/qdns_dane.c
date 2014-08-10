#include <qdns_dane.h>

#include <fmt.h>
#include <qdns.h>

#include <byte.h>
#include <dns.h>
#include <errno.h>
#include <stdlib.h>
#include <stralloc.h>
#include <string.h>
#include <uint16.h>

#define DNS_T_TLSA "\0\64"
#define TLSA_DATA_LEN 32
#define TLSA_RECORD_LEN (TLSA_DATA_LEN + 3)

/* taken from dns_txt_packet() of libowfat */
static int
dns_tlsa_packet(stralloc *out, const char *buf, unsigned int len)
{
	unsigned int pos;
	char header[12];
	uint16 numanswers;
	
	if (!stralloc_copys(out, ""))
		return -1;
	
	pos = dns_packet_copy(buf, len, 0, header, 12);
	if (!pos)
		return -1;
	uint16_unpack_big(header + 6, &numanswers);
	pos = dns_packet_skipname(buf, len, pos);
	if (!pos)
		return -1;
	pos += 4;

	while (numanswers--) {
		uint16 datalen;

		pos = dns_packet_skipname(buf, len, pos);
		if (!pos)
			return -1;
		pos = dns_packet_copy(buf, len, pos, header, 10);
		if (!pos)
			return -1;
		uint16_unpack_big(header + 8, &datalen);

		if (byte_equal(header, 2, DNS_T_TLSA)) {
			if (byte_equal(header + 2, 2, DNS_C_IN)) {
				if (pos + datalen > len) {
					errno = EINVAL;
					return -1;
					
				}
				stralloc_copyb(out, buf + pos, datalen);
			}
		}
		pos += datalen;
	}
	
	return 0;
}

static char *q = 0;

static int
dns_tlsa(stralloc *out, const stralloc *fqdn)
{
	if (!dns_domain_fromdot(&q, fqdn->s, fqdn->len))
		return -1;
	if (dns_resolve(q, DNS_T_TLSA) == -1)
		return -1;
	if (dns_tlsa_packet(out, dns_resolve_tx.packet, dns_resolve_tx.packetlen) == -1)
		return -1;
	dns_transmit_free(&dns_resolve_tx);
	dns_domain_free(&q);
	return 0;
}

int
dnstlsa(const char *host, const unsigned short port, struct daneinfo **out)
{
	char hostbuf[strlen("_65535._tcp.") + strlen(host) + 1];
	stralloc sa = {
		.a = 0,
		.len = 0,
		.s = NULL
	};
	stralloc fqdn = {
		.a = sizeof(hostbuf) - 1,
		.s = hostbuf
	};
	int r;

	hostbuf[0] = '_';
	ultostr(port, hostbuf + 1);
	strcat(hostbuf, "._tcp.");
	strcat(hostbuf, host);
	fqdn.len = strlen(hostbuf);

	r = dns_tlsa(&sa, &fqdn);
	if ((r != 0) || (sa.len == 0)) {
		free(sa.s);
		if (out != NULL)
			*out = NULL;
		return r;
	}

	if ((sa.len % TLSA_RECORD_LEN) != 0) {
		free(sa.s);
		if (out != NULL)
			*out = NULL;
		return DNS_ERROR_PERM;
	}

	r = (int)(sa.len / TLSA_RECORD_LEN);

	if (out != NULL) {
		struct daneinfo *res = calloc(r, sizeof(*res));
		int i;

		if (res == NULL) {
			free(sa.s);
			return DNS_ERROR_LOCAL;
		}
		*out = res;

		for (i = 0; i < r; i++) {
			res[i].cert_usage     = sa.s[i * TLSA_RECORD_LEN];
			res[i].selectors      = sa.s[i * TLSA_RECORD_LEN + 1];
			res[i].matching_types = sa.s[i * TLSA_RECORD_LEN + 2];
			memcpy(res[i].data, sa.s + i * TLSA_RECORD_LEN + 3, TLSA_DATA_LEN);
		}
	}

	free(sa.s);

	return r;
}
