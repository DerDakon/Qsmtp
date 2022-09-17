/** \file starttlsr.c
 \brief functions for SSL encoding and decoding of network I/O
 */

#include <qremote/starttlsr.h>

#include <control.h>
#include <log.h>
#include <netio.h>
#include <qdns.h>
#include <qdns_dane.h>
#include <qremote/qremote.h>
#include <ssl_timeoutio.h>
#include <sstring.h>
#include <tls.h>

#include <assert.h>
#include <fcntl.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <sys/stat.h>
#include <unistd.h>

const char *clientcertname = "control/clientcert.pem";
const char *clientkeyname = "control/clientcert.pem";

/**
 * @brief send STARTTLS and handle the connection setup
 * @param d the dane information received for that domain
 * @param cnt number of entries in d
 * @return if connection was successfully established
 * @retval 0 SSL mode successfully set up
 * @retval >0 SSL setup failed (non-local fault, e.g. network or reply error)
 * @retval <0 SSL setup failed (local fault, e.g. unable to load file)
 * @retval EDONE a network error happened but the connection may still be intact
 *
 * If the return value is <0 a status code for qmail-rspawn was already written.
 */
int
tls_init(const struct daneinfo *tlsa_info, int tlsa_cnt)
{
	char **saciphers;
	const char *ciphers;
	size_t fqlen = 0;
	const char fnprefix[] = "control/tlshosts/";
	const char fnsuffix[] = ".pem";
	char servercert[strlen(fnprefix) + DOMAINNAME_MAX + strlen(fnsuffix) + 1];

	if (partner_fqdn == NULL) {
		*servercert = '\0';
	} else {
		struct stat st;

		fqlen = strlen(partner_fqdn);
		assert(fqlen <= DOMAINNAME_MAX);
		memcpy(servercert, fnprefix, strlen(fnprefix));
		memcpy(servercert + strlen(fnprefix), partner_fqdn, fqlen);
		/* copy including the trailing '\0' */
		memcpy(servercert + strlen(fnprefix) + fqlen, fnsuffix, strlen(fnsuffix) + 1);
		if (stat(servercert, &st))
			*servercert = '\0';
	}

	SSL_library_init();
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ctx) {
		const char *msg[] = { "Z4.5.0 TLS error initializing ctx: ", ssl_error(), "; connecting to ",
				rhost };

		write_status_m(msg, 4);
		return -1;
	}

	/* disable obsolete and insecure protocol versions */
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	if (*servercert && !SSL_CTX_load_verify_locations(ctx, servercert, NULL)) {
		const char *msg[] = { "Z4.5.0 TLS unable to load ", servercert, ": ",
				ssl_error(),  "; connecting to ", rhost };

		write_status_m(msg, 6);
		SSL_CTX_free(ctx);
		ssl_library_destroy();
		return -1;
	}

	/* let the other side complain if it needs a cert and we don't have one */
	if (SSL_CTX_use_certificate_chain_file(ctx, clientcertname) == 1)
		SSL_CTX_use_RSAPrivateKey_file(ctx, clientkeyname, SSL_FILETYPE_PEM);

	int tlsa_usable = 0;
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
#if (OPENSSL_VERSION_NUMBER >= 0x10101000L) && !defined(LIBRESSL_VERSION_NUMBER)
	SSL_CTX_set_post_handshake_auth(ctx, 1);
#endif
	if (tlsa_cnt > 0) {
		/* find out if there is a usable record at all */
		for (int i = 0; i < tlsa_cnt; i++) {
			/* see SSL_dane_enable() manpage */
			switch (tlsa_info[i].cert_usage) {
			default:
			case 0:     /* PKIX-TA(0) */
			case 1:     /* PKIX-EE(1) */
				continue;
			case 2:     /* DANE-TA(2) */
			case 3:     /* DANE-EE(3) */
				tlsa_usable++;
				break;
			}
		}

		if (tlsa_usable == 0) {
			tlsa_cnt = 0;
		} else {
			if (SSL_CTX_dane_enable(ctx) <= 0) {
				const char *msg[] = { "Z4.5.0 TLS unable to activate DANE: ", ssl_error(), "; connecting to ",
						rhost };

				write_status_m(msg, 4);
				SSL_CTX_free(ctx);
				ssl_library_destroy();
				return -1;
			}
		}
	}
#else
	(void) tlsa_info;
	(void) tlsa_cnt;
#endif

	SSL *myssl = SSL_new(ctx);
	SSL_CTX_free(ctx);
	if (!myssl) {
		const char *msg[] = { "Z4.5.0 TLS error initializing ssl: ", ssl_error(), "; connecting to ",
				rhost };

		write_status_m(msg, 4);
		ssl_library_destroy();
		return -1;
	}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	if (tlsa_cnt > 0) {
		if (SSL_dane_enable(myssl, partner_fqdn) <= 0) {
			const char *msg[] = { "Z4.5.0 TLS error setting DANE host: ", ssl_error(), "; connecting to ",
					rhost };

			write_status_m(msg, 4);
			ssl_free(myssl);
			return -1;
		}

		/* taken from the SSL_dane_enable() manpage, not sure if this is the best idea */
		SSL_dane_set_flags(myssl, DANE_FLAG_NO_DANE_EE_NAMECHECKS);
		SSL_set_hostflags(myssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

		for (int i = 0; i < tlsa_cnt; i++) {
			/* see SSL_dane_enable() manpage */
			switch (tlsa_info[i].cert_usage) {
			default:
			case 0:     /* PKIX-TA(0) */
			case 1:     /* PKIX-EE(1) */
				continue;
			case 2:     /* DANE-TA(2) */
			case 3:     /* DANE-EE(3) */
				break;
			}

			int ret = SSL_dane_tlsa_add(myssl, tlsa_info[i].cert_usage, tlsa_info[i].selector, tlsa_info[i].matching_type,
					tlsa_info[i].data, tlsa_info[i].datalen);

			if (ret < 0) {
				const char *msg[] = { "Z4.5.0 TLS error adding DANE setting: ", ssl_error(), "; connecting to ",
						rhost };

				write_status_m(msg, 4);
				ssl_free(myssl);
				return -1;
			} else if (ret == 0) {
				/* handle unusable TLSA record */
				if (--tlsa_usable == 0) {
					const char *msg[] = { "only unusable DANE records found for ", rhost, NULL };

					log_writen(LOG_INFO, msg);
					break;
				}
			}
		}
	}
#endif

	if (*servercert) {
		X509_VERIFY_PARAM *vparam = SSL_get0_param(myssl);

		/* Enable automatic hostname checks */
		X509_VERIFY_PARAM_set_hostflags(vparam, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		if (X509_VERIFY_PARAM_set1_host(vparam, partner_fqdn, fqlen) != 1) {
			const char *msg[] = { "Z4.5.0 TLS error setting partner FQDN for verification: ", ssl_error(), "; connecting to ",
					rhost };

			write_status_m(msg, 4);
			ssl_library_destroy();
			return -1;
		}
	}
	SSL_set_verify(myssl, SSL_VERIFY_NONE, NULL);

	netwrite("STARTTLS\r\n");

	/* while the server is preparing a response, do something else */
	if (loadlistfd(openat(controldir_fd, "tlsclientciphers", O_RDONLY | O_CLOEXEC), &saciphers, NULL) == -1) {
		ssl_free(myssl);
		err_conf("can't open tlsclientciphers\n");
	}
	if (saciphers) {
		// overwrite the '\0' before any later entry with ':' to have a list that OpenSSL understand
		for (int i = 1; saciphers[i] != NULL; i++)
			saciphers[i][-1] = ':';
		ciphers = saciphers[0];
	} else {
		ciphers = "DEFAULT";
	}
	int i = SSL_set_cipher_list(myssl, ciphers);
	free(saciphers);
	if (i != 1) {
		ssl_free(myssl);
		err_conf("can't set ciphers\n");
	}

	i = SSL_set_fd(myssl, socketd);
	if (i != 1) {
		const char *msg[] = { "Z4.5.0 TLS error setting fd: ", ssl_error(), "; connecting to ",
				rhost };

		write_status_m(msg, 4);
		ssl_free(myssl);
		return -1;
	}

	/* read the response to STARTTLS */
	i = netget(0);
	while ((i > 0) && (linein.s[3] == '-')) {
		int k = netget(0);
		if (i != k) {
			if (k < 0)
				i = k;
			else
				i = EDONE;
			break;
		}
	}
	if (i != 220) {
		const char *msg[] = { "STARTTLS failed at ",
				rhost, ": ", linein.s, NULL };

		ssl_free(myssl);
		log_writen(LOG_ERR, msg);

		return i < 0 ? -i : EDONE;
	}

	i = ssl_timeoutconn(myssl, timeout);
	if (i < 0) {
		const char *msg[] = { "TLS connection failed at ", rhost, ": ", ssl_strerror(), NULL };

		log_writen(LOG_ERR, msg);
		ssl_free(myssl);
		return -i;
	}

	ssl = myssl;
	if (*servercert || tlsa_usable > 0) {
		long r = SSL_get_verify_result(myssl);

		if (r != X509_V_OK) {
			const char *msg[] = { "unable to verify ", rhost, " with ", servercert,
					": ", X509_verify_cert_error_string(r), NULL };

			log_writen(LOG_ERR, msg);
			return EDONE;
		}
	}

	return 0;
}
