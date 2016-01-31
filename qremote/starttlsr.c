/** \file starttlsr.c
 \brief functions for SSL encoding and decoding of network I/O
 */

#include <qremote/starttlsr.h>

#include <control.h>
#include <log.h>
#include <netio.h>
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

static int
match_partner(const struct string *peer)
{
	assert(partner_fqdn != NULL);

	/* the test on partner_fqdn[peer->len] is only done if the head matches, so it
	 * can only be 1 byte after the match (== '\0') and can't overflow */
	if (!strncasecmp(partner_fqdn, peer->s, peer->len) && (partner_fqdn[peer->len] == '\0'))
		return 1;
	/* we also match if the name is *.domainname */
	if ((peer->s[0] == '*') && (peer->s[1] == '.')) {
		const size_t clen = peer->len - 1;
		const size_t plen = strlen(partner_fqdn);

		/* match against the end of the string */
		/* match is done including the '.', so it's sure it really is a subdomain */
		if ((clen < plen) && (strcasecmp(partner_fqdn + plen - clen, peer->s + 1) == 0))
			return 1;
	}
	return 0;
}

static void
log_failed_peer(const struct string *peer)
{
	char buf[peer->len + 1];
	const char *msg[] = { "unable to verify ", rhost,
		": received certificate for '", buf, "'", NULL };
	size_t j;

	/* replace all special characters */
	for (j = 0; j < peer->len; ++j) {
		if ( (peer->s[j] < 32) || (peer->s[j] > 126) )
			buf[j] = '?';
		else
			buf[j] = peer->s[j];
	}
	buf[peer->len] = '\0';
	log_writen(LOG_ERR, msg);
}

/**
 * @brief send STARTTLS and handle the connection setup
 * @return if connection was successfully established
 * @retval 0 SSL mode successfully set up
 * @retval >0 SSL setup failed (non-local fault, e.g. network or reply error)
 * @retval <0 SSL setup failed (local fault, e.g. unable to load file)
 * @retval EDONE a network error happened but the connection may still be intact
 *
 * If the return value is <0 a status code for qmail-rspawn was already written.
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
		/* copy including the trailing '\0' */
		memcpy(tmp + 17 + fqlen, ".pem", 5);
		if (stat(tmp, &st))
			free(tmp);
		else
			servercert = tmp;
	}

	SSL_library_init();
	ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ctx) {
		const char *msg[] = { "Z4.5.0 TLS error initializing ctx: ", ssl_error(), "; connecting to ",
				rhost };

		write_status_m(msg, 4);
		free(servercert);
		return -1;
	}

	/* disable obsolete and insecure protocol versions */
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	if (servercert && !SSL_CTX_load_verify_locations(ctx, servercert, NULL)) {
		const char *msg[] = { "Z4.5.0 TLS unable to load ", servercert, ": ",
				ssl_error(),  "; connecting to ", rhost };

		write_status_m(msg, 6);
		SSL_CTX_free(ctx);
		free(servercert);
		ssl_library_destroy();
		return -1;
	}

	/* let the other side complain if it needs a cert and we don't have one */
	if (SSL_CTX_use_certificate_chain_file(ctx, clientcertname) == 1)
		SSL_CTX_use_RSAPrivateKey_file(ctx, clientcertname, SSL_FILETYPE_PEM);

	myssl = SSL_new(ctx);
	SSL_CTX_free(ctx);
	if (!myssl) {
		const char *msg[] = { "Z4.5.0 TLS error initializing ssl: ", ssl_error(), "; connecting to ",
				rhost };

		free(servercert);
		write_status_m(msg, 4);
		ssl_library_destroy();
		return -1;
	}
	SSL_set_verify(myssl, SSL_VERIFY_NONE, NULL);

	netwrite("STARTTLS\r\n");

	/* while the server is preparing a response, do something else */
	if (loadlistfd(openat(controldir_fd, "tlsclientciphers", O_RDONLY | O_CLOEXEC), &saciphers, NULL) == -1) {
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
		free(servercert);
		log_writen(LOG_ERR, msg);

		return i < 0 ? -i : EDONE;
	}

	ssl = myssl;
	i = ssl_timeoutconn(timeout);
	if (i < 0) {
		const char *msg[] = { "TLS connection failed at ", rhost, ": ", ssl_strerror(), NULL };

		free(servercert);
		log_writen(LOG_ERR, msg);
		return -i;
	}

	if (servercert) {
		X509 *peercert;
		STACK_OF(GENERAL_NAME) *gens;
		long r = SSL_get_verify_result(ssl);
		int found_match = 0;
		string peer = STREMPTY_INIT;

		if (r != X509_V_OK) {
			const char *msg[] = { "unable to verify ", rhost, " with ", servercert,
					": ", X509_verify_cert_error_string(r), NULL };

			log_writen(LOG_ERR, msg);
			free(servercert);
			return EDONE;
		}
		free(servercert);

		peercert = SSL_get_peer_certificate(ssl);
		if (!peercert) {
			const char *msg[] = { "unable to verify ", rhost,
					": no certificate provided", NULL };

			log_writen(LOG_ERR, msg);
			return EDONE;
		}

		/* RFC 2595 section 2.4: find a matching name
		 * first find a match among alternative names */
		gens = X509_get_ext_d2i(peercert, NID_subject_alt_name, 0, 0);
		if (gens) {
			int found_an = 0;	/* if a dNSName SubjectAltName was found */
			for (i = 0, r = sk_GENERAL_NAME_num(gens); i < r; ++i) {
				const GENERAL_NAME *gn = sk_GENERAL_NAME_value(gens, i);

				if (gn->type == GEN_DNS) {
					found_an = 1;
					peer.len = gn->d.ia5->length;
					peer.s = (char *)gn->d.ia5->data;
					found_match = match_partner(&peer);
					if (found_match)
						break;
				}
			}

			/* if a dNSName SubjectAltName was found it must be used, i.e.
			 * commonName is ignored then */
			if (found_an && !found_match) {
				log_failed_peer(&peer);
				sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
				X509_free(peercert);
				return EDONE;
			}
			sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
		}

		/* no alternative name matched, look up commonName,
		 * but only if no dNSName SubjectAltName was present */
		if (!found_match) {
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
				const char *msg[] = { "unable to verify ", rhost,
						": certificate contains no valid commonName", NULL };

				X509_free(peercert);
				log_writen(LOG_ERR, msg);
				return EDONE;
			}
			if (!match_partner(&peer)) {
				log_failed_peer(&peer);
				X509_free(peercert);
				return EDONE;
			}
		}

		X509_free(peercert);
	}

	return 0;
}
