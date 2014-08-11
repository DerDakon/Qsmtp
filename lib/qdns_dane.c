#include <qdns_dane.h>

#include <fmt.h>
#include <qdns.h>

#include <dns.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define DNS_T_TLSA "\0\64"
#define TLSA_DATA_LEN_SHA256 (256 / 8)
#define TLSA_DATA_LEN_SHA512 (512 / 8)
#define TLSA_MIN_RECORD_LEN 3

static int
free_tlsa_data(struct daneinfo **out, const int cnt)
{
	int i;

	if (out != NULL) {
		for (i = 0; i < cnt; i++)
			free(out[i]->data);
		free(*out);
		*out = NULL;
	}

	return -1;
}

/* taken from dns_txt_packet() of libowfat */
static int
dns_tlsa_packet(struct daneinfo **out, const char *buf, unsigned int len)
{
	unsigned int pos;
	char header[12];
	uint16_t numanswers;
	int ret = 0;

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

	if (out != NULL) {
		*out = calloc(numanswers, sizeof(**out));
		if (*out == NULL)
			return -1;
	}

	while (numanswers--) {
		uint16_t datalen;

		pos = dns_packet_skipname(buf, len, pos);
		if (!pos)
			return free_tlsa_data(out, ret);
		if (len < pos + 10) {
			errno = EINVAL;
			return free_tlsa_data(out, ret);
		}
		memcpy(header, buf + pos, 10);
		pos += 10;
		datalen = ntohs(*((unsigned short *)(header + 8)));

		if (memcmp(header, DNS_T_TLSA, 2) == 0) {
			if (memcmp(header + 2, DNS_C_IN, 2) == 0) {
				unsigned int minlen;
				unsigned int maxlen;

				if (datalen <= TLSA_MIN_RECORD_LEN) {
					errno = EINVAL;
					return free_tlsa_data(out, ret);
				}

				if (pos + datalen > len) {
					errno = EINVAL;
					return free_tlsa_data(out, ret);
					
				}

				switch (buf[pos + 2]) {
				default:
				case TLSA_MT_Full:
					minlen = 1;
					maxlen = datalen;
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

				if ((datalen < minlen + TLSA_MIN_RECORD_LEN) || (datalen > maxlen + TLSA_MIN_RECORD_LEN)) {
					errno = EINVAL;
					return free_tlsa_data(out, ret);
				}

				if (out != NULL) {
					struct daneinfo *res = out[ret];

					res->cert_usage = buf[pos];
					res->selector = buf[pos + 1];
					res->matching_type = buf[pos + 2];
					res->datalen = datalen - TLSA_MIN_RECORD_LEN;
					res->data = malloc(res->datalen);

					if (res->data == NULL)
						return free_tlsa_data(out, ret);

					memcpy(res->data, buf + pos + TLSA_MIN_RECORD_LEN, res->datalen);
					ret++;
				}
			}
		}
		pos += datalen;
	}

	return ret;
}

static int
dns_tlsa(struct daneinfo **out, const stralloc *fqdn)
{
	char *q = NULL;
	int r;

	if (!dns_domain_fromdot(&q, fqdn->s, fqdn->len))
		return -1;
	if (dns_resolve(q, DNS_T_TLSA) == -1)
		return -1;
	r = dns_tlsa_packet(out, dns_resolve_tx.packet, dns_resolve_tx.packetlen);
	if (r < 0)
		return r;
	dns_transmit_free(&dns_resolve_tx);
	dns_domain_free(&q);
	return r;
}

int
dnstlsa(const char *host, const unsigned short port, struct daneinfo **out)
{
	char hostbuf[strlen("_65535._tcp.") + strlen(host) + 1];
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

	if (out != NULL)
		*out = NULL;

	r = dns_tlsa(out, &fqdn);
	if (r <= 0) {
		if (out != NULL) {
			free(*out);
			*out = NULL;
		}
		return r;
	}

	return r;
}
