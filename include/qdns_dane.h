/** @file qdns_dane.h
 * @brief definitions for DNS DANE information
 */
#ifndef QDNS_DANE_H
#define QDNS_DANE_H

#include <stdint.h>
#include <sys/types.h>

/** @enum tlsa_cu
 * @brief labels for TLSA certificate usage values
 */
enum tlsa_cu {
	TLSA_CU_PKIX_TA = 0,	/**< CA constraint */
	TLSA_CU_PKIX_EE = 1,	/**< Service certificate constraint */
	TLSA_CU_DANE_TA = 2,	/**< Trust anchor assertion */
	TLSA_CU_DANE_EE = 3,	/**< Domain-issued certificate */
	TLSA_CU_PrivCert = 255	/**< Reserved for Private Use */
};

/** @enum tlsa_sel
 * @brief labels for TLSA selector values
 */
enum tlsa_sel {
	TLSA_SEL_Cert = 0,	/**< Full certificate */
	TLSA_SEL_SPKI = 1,	/**< SubjectPublicKeyInfo */
	TLSA_SEL_PrivSel = 255	/**< Reserved for Private Use */
};

/** @enum tlsa_mt
 * @brief labels for TLSA matching type values
 */
enum tlsa_mt {
	TLSA_MT_Full = 0,	/**< No hash used */
	TLSA_MT_SHA2_256 = 1,	/**< 256 bit hash by SHA2 */
	TLSA_MT_SHA2_512 = 2,	/**< 512 bit hash by SHA2 */
	TLSA_MT_PrivMatch = 255	/**< Reserved for Private Use */
};

/** @struct daneinfo
 * @brief contents of one DNS DANE record
 */
struct daneinfo {
	unsigned char cert_usage;
	unsigned char selector;
	unsigned char matching_type;
	unsigned char *data;
	size_t datalen;	/**< length of data */
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
extern int dnstlsa(const char *host, const unsigned short port, struct daneinfo **out) __attribute__((nonnull (1)));

extern void daneinfo_free(struct daneinfo *di, int cnt);

#endif /* QDNS_DANE_H */
