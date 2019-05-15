/** \file libowfatconn.c
 \brief connector functions for libowfat DNS functions
 */

#include <libowfatconn.h>

#include <byte.h>
#include <dns.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <stralloc.h>
#include <string.h>
#include <uint16.h>

/**
 * @brief handle the libowfat return codes
 *
 * @param sa the result buffer passed to libowfat function
 * @param out result string from sa will be stored here on success
 * @param len length of out
 * @param r return code from libowfat function
 * @return r
 *
 * libowfat functions can allocate memory into sa even if the function
 * returns with an error. Also memory will be allocated even if the function
 * returns 0 and sa.len is 0. Make sure the memory is freed in this cases.
 */
static int
mangle_ip_ret(struct stralloc *sa, char **out, size_t *len, int r)
{
	if ((r != 0) || (sa->len == 0)) {
		free(sa->s);
		*out = NULL;
		*len = 0;
	} else {
		*out = sa->s;
		*len = sa->len;
	}
	return r;
}

/**
 * @brief create a stralloc for the given string
 *
 * Even if the s member of the stralloc is not const, we
 * trust everyone who takes a const stralloc not to change it.
 */
#define const_stralloc_from_string(str) \
	{ \
		.a = strlen(str) + 1, \
		.len = strlen(str), \
		.s = (char *)str \
	}

/**
 * @brief query DNS for IPv6 address of host
 *
 * @param out result string will be stored here, memory is malloced
 * @param len length of out
 * @param host host name to look up
 * @retval 0 success
 * @retval -1 an error occurred, errno is set
 */
int
dnsip6(char **out, size_t *len, const char *host)
{
	/* we can't use const_stralloc_from_string() here as dns_ip6()
	 * modifies it's second argument. */
	stralloc fqdn = {.a = 0, .len = 0, .s = NULL};
	stralloc sa = {.a = 0, .len = 0, .s = NULL};

	if (!stralloc_copys(&fqdn, host))
		return -1;

	int r = dns_ip6(&sa, &fqdn);
	free(fqdn.s);
	return mangle_ip_ret(&sa, out, len, r);
}

/**
 * @brief query DNS for IPv4 address of host
 *
 * @param out result string will be stored here, memory is malloced
 * @param len length of out
 * @param host host name to look up
 * @retval 0 success
 * @retval -1 an error occurred, errno is set
 */
int
dnsip4(char **out, size_t *len, const char *host)
{
	const stralloc fqdn = const_stralloc_from_string(host);
	stralloc sa = {.a = 0, .len = 0, .s = NULL};
	int r = dns_ip4(&sa, &fqdn);
	return mangle_ip_ret(&sa, out, len, r);
}

/**
 * @brief query DNS for MX entries
 *
 * @param out result string will be stored here, memory is malloced
 * @param len length of out
 * @param host host name to look up
 * @retval 0 success
 * @retval -1 an error occurred, errno is set
 */
int
dnsmx(char **out, size_t *len, const char *host)
{
	const stralloc fqdn = const_stralloc_from_string(host);
	stralloc sa = {.a = 0, .len = 0, .s = NULL};
	int r = dns_mx(&sa, &fqdn);
	return mangle_ip_ret(&sa, out, len, r);
}

/*
 * The next 2 functions are directly taken from libowfat. That's why they
 * have a different coding style. They are modified only to add 0 separators
 * between every result and pass the number of result records back to the
 * caller.
 */
static int
dns_txt_packet2(stralloc *out,const char *buf,unsigned int len)
{
  unsigned int pos;
  char header[12];
  uint16 numanswers;
  uint16 datalen;
  char ch;
  unsigned int txtlen;
  int i;
  int r = 0;

  if (!stralloc_copys(out,"")) return -1;

  pos = dns_packet_copy(buf,len,0,header,12); if (!pos) return -1;
  uint16_unpack_big(header + 6,&numanswers);
  pos = dns_packet_skipname(buf,len,pos); if (!pos) return -1;
  pos += 4;

  while (numanswers--) {
    pos = dns_packet_skipname(buf,len,pos); if (!pos) return -1;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) return -1;
    uint16_unpack_big(header + 8,&datalen);
    if (byte_equal(header,2,DNS_T_TXT)) {
      int subcount = 0;
      // concat multiple DNS strings
      if (byte_equal(header + 2,2,DNS_C_IN)) {
	if (pos + datalen > len) { errno = EINVAL; return -1; }
	txtlen = 0;
	for (i = 0;i < datalen;++i) {
	  ch = buf[pos + i];
	  if (!txtlen)
	    txtlen = (unsigned char) ch;
	  else {
	    --txtlen;
	    if (ch < 32) ch = '?';
	    if (ch > 126) ch = '?';
	    if (!stralloc_append(out,&ch)) return -1;
	  }
	}
	subcount++;
      }
      if (subcount > 0) {
        // if at least one string was received add a record separator
        if (!stralloc_0(out)) return -1;
        r++;
      }
    }
    pos += datalen;
  }

  return r;
}

static int
dns_txt2(stralloc *out,const stralloc *fqdn)
{
  char *q = NULL;
  int r;
  if (!dns_domain_fromdot(&q,fqdn->s,fqdn->len)) return -1;
  if (dns_resolve(q,DNS_T_TXT) == -1) return -1;
  r = dns_txt_packet2(out,dns_resolve_tx.packet,dns_resolve_tx.packetlen);
  if (r < 0) return r;
  dns_transmit_free(&dns_resolve_tx);
  dns_domain_free(&q);
  return r;
}

/**
 * @brief query DNS for TXT entries, return records as a sequence of strings and 0-bytes
 *
 * @param out TXT record of host will be stored here, memory is malloced
 * @param host name of host to look up
 * @retval 0 success
 * @retval -1 an error occurred, errno is set
 */
int
dnstxt_records(char **out, const char *host)
{
	stralloc sa = {.a = 0, .len = 0, .s = NULL};
	const stralloc fqdn = const_stralloc_from_string(host);
	int r = dns_txt2(&sa, &fqdn);

	if (r <= 0) {
		free(sa.s);
		*out = NULL;
		return r;
	}

	*out = sa.s;

	return r;
}

/**
 * @brief query DNS for TXT entries and concat them to a single string
 *
 * @param out TXT record of host will be stored here, memory is malloced
 * @param host name of host to look up
 * @retval 0 success
 * @retval -1 an error occurred, errno is set
 */
int
dnstxt(char **out, const char *host)
{
	stralloc sa = {.a = 0, .len = 0, .s = NULL};
	const stralloc fqdn = const_stralloc_from_string(host);
	int r = dns_txt(&sa, &fqdn);

	if ((r != 0) || (sa.len == 0)) {
		free(sa.s);
		*out = NULL;
		return r;
	}

	r = stralloc_0(&sa);

	if (!r) {
		free(sa.s);
		return -1;
	}

	*out = sa.s;
	return 0;
}

/**
 * @brief query DNS for name for a given IP address
 *
 * @param out DNS name of host will be stored here, memory is malloced
 * @param ip IPv6 address of host to look up
 * @retval 0 success
 * @retval -1 an error occurred, errno is set
 */
int
dnsname(char **out, const struct in6_addr *ip)
{
	stralloc sa = {.a = 0, .len = 0, .s = NULL};
	int r = dns_name6(&sa, (const char *)ip->s6_addr);

	if ((r != 0) || (sa.len == 0)) {
		free(sa.s);
		*out = NULL;
		return r;
	}
	if (!stralloc_0(&sa)) {
		free(sa.s);
		return -1;
	}
	*out = sa.s;
	return 0;
}
