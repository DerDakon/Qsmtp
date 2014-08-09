/** @file qdns_dane.h
 * @brief definitions for DNS DANE information
 */
#ifndef QDNS_DANE_H
#define QDNS_DANE_H

#include <stdint.h>

/** @struct daneinfo
 * @brief contents of one DNS DANE record
 */
struct daneinfo {
	unsigned char cert_usage;
	unsigned char selectors;
	unsigned char matching_types;
	uint32_t data[8];
};

/**
 * @brief check for TLSA record of the given host
 * @param host the host name to check
 * @param port the port of the host to check
 * @param out if not NULL TLSA info will be returned here
 * @return the number of TLSA entries
 * @retval <0 error code from dns_errors enum
 *
 * If out is NULL the return value is the number of structs that would
 * have been returned.
 *
 * The protocol in the DNS lookup is always _tcp.
 *
 * The DNS answers are NOT (yet?) checked for DNSSEC signatures.
 */
extern int dnstlsa(const char *host, const unsigned short port, struct daneinfo **out);

#endif /* QDNS_DANE_H */
