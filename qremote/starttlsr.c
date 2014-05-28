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

static void __attribute__ ((noreturn))
tls_quit(void)
{
	const char *msg[] = { ssl ? "; connected to " : "; connecting to ",
			rhost, "\n" };

	write_status_m(msg, 3);
	net_conn_shutdown(shutdown_clean);
}

static void  __attribute__ ((noreturn)) __attribute__ ((nonnull (1, 2)))
tls_quitmsg(const char *s1, const char *s2)
{
	write(1, s1, strlen(s1));
	write(1, ": ", 2);
	write(1, s2, strlen(s2));
	tls_quit();
}

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
		free(servercert);
		tls_quitmsg("Z4.5.0 TLS error initializing ctx", ssl_error());
	}

	if (servercert) {
		if (!SSL_CTX_load_verify_locations(ctx, servercert, NULL)) {
			SSL_CTX_free(ctx);
			write(1, "Z4.5.0 TLS unable to load ", 26);
			write(1, servercert, strlen(servercert));
			free(servercert);
			tls_quitmsg("", ssl_error());
		}
		/* set the callback here; SSL_set_verify didn't work before 0.9.6c */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	}

	/* let the other side complain if it needs a cert and we don't have one */
	if (SSL_CTX_use_certificate_chain_file(ctx, "control/clientcert.pem"))
		SSL_CTX_use_RSAPrivateKey_file(ctx, "control/clientcert.pem", SSL_FILETYPE_PEM);

	myssl = SSL_new(ctx);
	SSL_CTX_free(ctx);
	if (!myssl) {
		free(servercert);
		tls_quitmsg("Z4.5.0 TLS error initializing ssl", ssl_error());
	}

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
	SSL_set_cipher_list(myssl, ciphers);
	free(saciphers);

	/* SSL_set_options(myssl, SSL_OP_NO_TLSv1); */
	SSL_set_fd(myssl, socketd);

	/* read the responce to STARTTLS */
	if (netget() != 220) {
		const char *msg;
		ssl_free(myssl);

		if (!servercert) {
			msg = "Z4.5.0 STARTTLS rejected";
		} else {
			write(1, "Z4.5.0 STARTTLS rejected while ", 31);
			write(1, servercert, strlen(servercert));
			free(servercert);
			msg = " exists";
		}
		write(1, msg, strlen(msg));
		tls_quit();
	}

	ssl = myssl;
	if (ssl_timeoutconn(timeout) <= 0) {
		free(servercert);
		tls_quitmsg("Z4.5.0 TLS connect failed", ssl_strerror());
	}

	if (servercert) {
		X509 *peercert;
		STACK_OF(GENERAL_NAME) *gens;
		long r = SSL_get_verify_result(ssl);

		if (r != X509_V_OK) {
			write(1, "Z4.5.0 TLS unable to verify server with ", 40);
			tls_quitmsg(servercert, X509_verify_cert_error_string(r));
		}
		free(servercert);

		peercert = SSL_get_peer_certificate(ssl);
		if (!peercert) {
			write(1, "Z4.5.0 TLS unable to verify server ", 35);
			tls_quitmsg(partner_fqdn, "no certificate provided");
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
				write(1, "Z4.5.0 TLS unable to verify server ", 35);
				// FIXME: X509_free(peercert); ?
				tls_quitmsg(partner_fqdn, "certificate contains no valid commonName");
			}
			if (!match_partner(peer.s, peer.len)) {
				char buf[64];
				int idx = 0;
				size_t j;

				write(1, "Z4.5.0 TLS unable to verify server ", 35);
				write(1, partner_fqdn, fqlen);
				write(1, ": received certificate for ", 27);
				for (j = 0; j < peer.len; ++j) {
					if ( (peer.s[j] < 33) || (peer.s[j] > 126) ) {
						buf[idx++] = '?';
					} else {
						buf[idx++] = peer.s[j];
					}
					if (idx == sizeof(buf)) {
						write(1, buf, sizeof(buf));
						idx = 0;
					}
				}
				write(1, buf, idx);
				// FIXME: X509_free(peercert); ?
				tls_quit();
			}
		}

		X509_free(peercert);
	}

	return 1;
}
