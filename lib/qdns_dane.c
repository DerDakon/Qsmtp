#include <qdns_dane.h>

#include <fmt.h>
#include <qdns.h>

#include <dns.h>
#include <errno.h>
#include <stdlib.h>
#include <stralloc.h>
#include <string.h>

#define DNS_T_TLSA "\0\64"
#define TLSA_DATA_LEN_SHA256 (256 / 8)
#define TLSA_DATA_LEN_SHA512 (512 / 8)
#define TLSA_MIN_RECORD_LEN 3

/* taken from dns_txt_packet() of libowfat */
static int
dns_tlsa_packet(stralloc *out, const char *buf, unsigned int len)
{
	unsigned int pos;
	char header[12];
	uint16_t numanswers;

	if (!stralloc_copys(out, ""))
		return -1;

	if (len < sizeof(header)) {
		errno = EINVAL;
		return -1;
	}
	memcpy(header, buf, sizeof(header));

	numanswers = ntohs(*((unsigned short *)(header + 6)));
	pos = dns_packet_skipname(buf, len, sizeof(header));
	if (!pos)
		return -1;
	pos += 4;

	while (numanswers--) {
		uint16_t datalen;

		pos = dns_packet_skipname(buf, len, pos);
		if (!pos)
			return -1;
		if (len < pos + 10) {
			errno = EINVAL;
			return -1;
		}
		memcpy(header, buf + pos, 10);
		pos += 10;
		datalen = ntohs(*((unsigned short *)(header + 8)));

		if (memcmp(header, DNS_T_TLSA, 2) == 0) {
			if (memcmp(header + 2, DNS_C_IN, 2) == 0) {
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


static int
dns_tlsa(stralloc *out, const stralloc *fqdn)
{
	char *q = NULL;

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
	size_t off = 0;

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

	if (sa.len < TLSA_MIN_RECORD_LEN) {
		free(sa.s);
		if (out != NULL)
			*out = NULL;
		return DNS_ERROR_PERM;
	}

	if (out != NULL)
		*out = NULL;

	r = 0;

	while (off < sa.len) {
		struct daneinfo tmp = {
			.cert_usage = sa.s[off],
			.selector = sa.s[off + 1],
			.matching_type = sa.s[off + 2]
		};
		unsigned int minlen;
		unsigned int maxlen;

		off += TLSA_MIN_RECORD_LEN;

		switch (tmp.matching_type) {
		default:
		case TLSA_MT_Full:
			minlen = 0;
			/* probably wrong, but no idea how to properly detect that */
			maxlen = sa.len - off;
			break;
		case TLSA_MT_SHA2_256:
			minlen = TLSA_DATA_LEN_SHA256;
			maxlen = TLSA_DATA_LEN_SHA256;
			break;
		case TLSA_MT_SHA2_512:
			minlen = TLSA_DATA_LEN_SHA512;
			maxlen = TLSA_DATA_LEN_SHA512;
			break;
		}

		if (sa.len - off < minlen) {
			if (out != NULL)
				free(*out);
			free(sa.s);
			return DNS_ERROR_PERM;
		}

		if (out != NULL) {
			struct daneinfo *res = realloc(*out, sizeof(*res) * (r + 1));

			tmp.data = malloc(maxlen);

			if ((res == NULL) || (tmp.data == NULL)) {
				int j;
				for (j = 0; j < r; j++)
					free((*out)[j].data);
				free(*out);
				free(sa.s);
				return DNS_ERROR_LOCAL;
			}

			memcpy(tmp.data, sa.s + off, maxlen);

			tmp.datalen = maxlen;
			res[r++] = tmp;
			*out = res;
		}

		off += maxlen;
	}

	free(sa.s);

	return r;
}
