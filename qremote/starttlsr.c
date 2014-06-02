/** \file starttlsr.c
 \brief functions for SSL encoding and decoding of network I/O
 */
#include <openssl/x509v3.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include "tls.h"
#include "ssl_timeoutio.h"
#include <qremote/qremote.h>
#include "control.h"
#include "netio.h"
#include "sstring.h"
#include <qremote/starttlsr.h>

static int
match_partner(const char *s, size_t len)
{
	if (!partner_fqdn)
		return 0;

	if (!strncasecmp(partner_fqdn, s, len) && !partner_fqdn[len])
		return 1;
	/* we also match if the name is *.domainname */
	if (*s == '*') {
		const char *domain = strchr(partner_fqdn, '.');

		if (!domain)
			return 0;
		if (!strncasecmp(domain, ++s, --len) && !domain[len])
			return 1;
	}
	return 0;
}

/**
 * @brief send STARTTLS and handle the connection setup
 * @return if connection was successfully established
 * @retval 0 SSL mode successfully set up
 * @retval 1 SSL setup failed, transmission should be terminated
 */
int
tls_init(void)
{
	int i = 0;
	SSL *myssl;
	SSL_CTX *ctx;
	char **saciphers, *servercert = NULL;
	const char *ciphers;
	size_t fqlen = 0;

	if (partner_fqdn) {
		char *tmp;
		struct stat st;

		fqlen = strlen(partner_fqdn);
		tmp = malloc(fqlen + 22);
		if (!tmp)
			err_mem(1);
		memcpy(tmp, "control/tlshosts/", 17);
		memcpy(tmp + 17, partner_fqdn, fqlen);
		memcpy(tmp + 17 + fqlen, ".pem", 5);
		if (stat(tmp, &st)) {
			free(tmp);
		} else {
			servercert = tmp;
		}
	}

	SSL_library_init();
	ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ctx) {
		const char *msg[] = { "Z4.5.0 TLS error initializing ctx: ", ssl_error(), "; connecting to ",
				rhost };

		write_status_m(msg, 4);
		free(servercert);
		return 1;
	}

	if (servercert) {
		if (!SSL_CTX_load_verify_locations(ctx, servercert, NULL)) {
			const char *msg[] = { "Z4.5.0 TLS unable to load ", servercert, ": ",
					ssl_error(),  "; connecting to ", rhost };

			write_status_m(msg, 6);
			SSL_CTX_free(ctx);
			free(servercert);
			ssl_library_destroy();
			return 1;
		}
	}

	/* let the other side complain if it needs a cert and we don't have one */
	if (SSL_CTX_use_certificate_chain_file(ctx, "control/clientcert.pem"))
		SSL_CTX_use_RSAPrivateKey_file(ctx, "control/clientcert.pem", SSL_FILETYPE_PEM);

	myssl = SSL_new(ctx);
	SSL_CTX_free(ctx);
	if (!myssl) {
		const char *msg[] = { "Z4.5.0 TLS error initializing ssl: ", ssl_error(), "; connecting to ",
				rhost };

		free(servercert);
		write_status_m(msg, 4);
		ssl_library_destroy();
		return 1;
	}
	SSL_set_verify(myssl, SSL_VERIFY_NONE, NULL);

	netwrite("STARTTLS\r\n");

	/* while the server is preparing a responce, do something else */
	if (loadlistfd(open("control/tlsclientciphers", O_RDONLY), &saciphers, NULL) == -1) {
		free(servercert);
		ssl_free(myssl);
		err_conf("can't open tlsclientciphers\n");
	}
	if (saciphers) {
		while (saciphers[i + 1]) {
			saciphers[i][strlen(saciphers[i])] = ':';
			i++;
		}
		ciphers = saciphers[0];
	} else {
		ciphers = "DEFAULT";
	}
	i = SSL_set_cipher_list(myssl, ciphers);
	free(saciphers);
	if (i != 1) {
		free(servercert);
		ssl_free(myssl);
		err_conf("can't set ciphers\n");
	}

	i = SSL_set_fd(myssl, socketd);
	if (i != 1) {
		const char *msg[] = { "Z4.5.0 TLS error setting fd: ", ssl_error(), "; connecting to ",
				rhost };

		free(servercert);
		write_status_m(msg, 4);
		ssl_free(myssl);
		return 1;
	}

	/* read the responce to STARTTLS */
	if (netget() != 220) {
		const char *msg[] = { NULL, NULL, NULL,  "; connecting to ",
				rhost };
		unsigned int first;

		ssl_free(myssl);

		if (!servercert) {
			first = 2;
			msg[2] = "Z4.5.0 STARTTLS rejected";
		} else {
			first = 0;
			msg[0] = "Z4.5.0 STARTTLS rejected while ";
			msg[1] = servercert;
			msg[2] = " exists";
		}
		write_status_m(msg + first, 5 - first);
		free(servercert);
		return 1;
	}

	ssl = myssl;
	if (ssl_timeoutconn(timeout) <= 0) {
		const char *msg[] = { "Z4.5.0 TLS connect failed: ", ssl_strerror(), "; connecting to ",
				rhost };

		free(servercert);
		write_status_m(msg, 4);
		return 1;
	}

	if (servercert) {
		X509 *peercert;
		STACK_OF(GENERAL_NAME) *gens;
		long r = SSL_get_verify_result(ssl);

		if (r != X509_V_OK) {
			const char *msg[] = { "Z4.5.0 TLS unable to verify server with ", servercert,
					": ", X509_verify_cert_error_string(r), "; connected to ", rhost };

			write_status_m(msg, 6);
			free(servercert);
			return 1;
		}
		free(servercert);

		peercert = SSL_get_peer_certificate(ssl);
		if (!peercert) {
			const char *msg[] = { "Z4.5.0 TLS unable to verify server ", partner_fqdn,
					": no certificate provided; connected to ", rhost };

			write_status_m(msg, 4);
			return 1;
		}

		/* RFC 2595 section 2.4: find a matching name
		 * first find a match among alternative names */
		gens = X509_get_ext_d2i(peercert, NID_subject_alt_name, 0, 0);
		if (gens) {
			for (i = 0, r = sk_GENERAL_NAME_num(gens); i < r; ++i) {
				const GENERAL_NAME *gn = sk_GENERAL_NAME_value(gens, i);

				if (gn->type == GEN_DNS)
					if (match_partner((char *)gn->d.ia5->data, gn->d.ia5->length))
						break;
			}
			sk_GENERAL_NAME_free(gens);
		}

		/* no alternative name matched, look up commonName */
		if (!gens || i >= r) {
			string peer;

			STREMPTY(peer);
			X509_NAME *subj = X509_get_subject_name(peercert);
			i = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
			if (i >= 0) {
				const ASN1_STRING *s = X509_NAME_get_entry(subj, i)->value;

				if (s) {
					peer.len = s->length > 0 ? s->length : 0;
					peer.s = (char *)s->data;
				}
			}
			if (!peer.len) {
				const char *msg[] = { "Z4.5.0 TLS unable to verify server ", partner_fqdn,
						": certificate contains no valid commonName; connected to ", rhost };
					
				write_status_m(msg, 4);
				X509_free(peercert);
				return 1;
			}
			if (!match_partner(peer.s, peer.len)) {
				char buf[peer.len + 1];
				const char *msg[] = { "Z4.5.0 TLS unable to verify server ", partner_fqdn,
					": received certificate for ", buf, "; connected to ", rhost };
				size_t j;

				for (j = 0; j < peer.len; ++j) {
					if ( (peer.s[j] < 33) || (peer.s[j] > 126) )
						buf[j] = '?';
					else
						buf[j] = peer.s[j];
				}
				buf[peer.len] = '\0';
				X509_free(peercert);
				write_status_m(msg, 6);
				return 1;
			}
		}

		X509_free(peercert);
	}

	return 0;
}
