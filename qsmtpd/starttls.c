#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "tls.h"
#include "netio.h"
#include "control.h"
#include "dns.h"
#include "ssl_timeoutio.h"
#include "qsmtpd.h"

int tls_init(void);
int tls_verify(void);

int ssl_verified = 0;
const char *ssl_verify_err = 0;

#warning FIXME: initialize timeout somewhere
int timeout = 320;

int
smtp_starttls(void)
{
	if (ssl || !xmitstat.esmtp)
		return 1;
	return tls_init();
}

RSA *tmp_rsa_cb(SSL *s __attribute__ ((unused)), int export, int keylen)
{
	if (!export)
		keylen = 512;
	if (keylen == 512) {
		FILE *in = fopen("control/rsa512.pem", "r");
		if (in) {
			RSA *rsa = PEM_read_RSAPrivateKey(in, NULL, NULL, NULL);

			while (fclose(in) && (errno == EINTR));
			if (rsa)
				return rsa;
		}
	}
	return RSA_generate_key(keylen, RSA_F4, NULL, NULL);
}

DH *tmp_dh_cb(SSL *s __attribute__ ((unused)), int export, int keylen)
{
	FILE *in = NULL;

	if (!export)
		keylen = 1024;
	if (keylen == 512) {
		in = fopen("control/dh512.pem", "r");
	} else if (keylen == 1024) {
		in = fopen("control/dh1024.pem", "r");
	}
	if (in) {
		DH *dh = PEM_read_DHparams(in, NULL, NULL, NULL);

		while (fclose(in) && (errno == EINTR));
		if (dh)
			return dh;
	}
	return DH_generate_parameters(keylen, DH_GENERATOR_2, NULL, NULL);
}

void tls_out(const char *s1, const char *s2)
{
	const char *msg[] = {"454 TLS ", s1, "", "", " (#4.3.0)", NULL};
	
	if (s2) {
		msg[2] = ": ";
		msg[3] = s2;
	}
	net_writen(msg);
}

void tls_err(const char *s) { tls_out(s, ssl_error()); }

#define CLIENTCA "control/clientca.pem"
#define CLIENTCRL "control/clientcrl.pem"
#define SERVERCERT "control/servercert.pem"

int tls_verify(void)
{
	char *clientbuf, **clients;
	STACK_OF(X509_NAME) *sk = SSL_load_client_CA_file(CLIENTCA);
	int relayclient = 0;

	if (!ssl || xmitstat.authname.len || ssl_verified)
		return 0;
	ssl_verified = 1; /* don't do this twice */

	/* request client cert to see if it can be verified by one of our CAs
	* and the associated email address matches an entry in tlsclients */
	if ( loadlistfd(open("control/tlsclients", O_RDONLY), &clientbuf, &clients, checkaddr, 1) < 0 )
		return -1;

	/* if CLIENTCA contains all the standard root certificates, a
	* 0.9.6b client might fail with SSL_R_EXCESSIVE_MESSAGE_SIZE;
	* it is probably due to 0.9.6b supporting only 8k key exchange
	* data while the 0.9.6c release increases that limit to 100k */
	if (sk) {
		SSL_set_client_CA_list(ssl, sk);
		SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, NULL);
	} else {
		free(clients);
		free(clientbuf);
	}

	if (ssl_timeoutrehandshake(timeout) <= 0) {
		const char *err = ssl_strerror();
		tls_out("rehandshake failed", err);
		errno = EBADE;
		return -1;
	}

	do { /* one iteration */
		X509 *peercert;
		X509_NAME *subj;
		string email = { .len = 0, .s = NULL};
		int n = SSL_get_verify_result(ssl);

		if (n != X509_V_OK) {
			ssl_verify_err = X509_verify_cert_error_string(n);
			break;
		}
		peercert = SSL_get_peer_certificate(ssl);
		if (!peercert)
			break;

		subj = X509_get_subject_name(peercert);
		n = X509_NAME_get_index_by_NID(subj, NID_pkcs9_emailAddress, -1);
		if (n >= 0) {
			const ASN1_STRING *s = X509_NAME_get_entry(subj, n)->value;
			if (s) {
				email.len = s->length;
				email.s = s->data;
			}
		}

		if (email.len <= 0)
			ssl_verify_err = "contains no email address";
		else {
			unsigned int i = 0;
			while (clients[i]) {
				if (!strcmp(email.s, clients[i]))
					break;
				i++;
			}
			if (!clients[i])
				ssl_verify_err = "email address not in my list of tlsclients";
			else {
				int l = strlen(protocol);

				protocol = realloc(protocol, l + 9 + email.len);
				if (!protocol) {
					free(clients);
					free(clientbuf);
					return ENOMEM;
				}
				/* add the cert email to the protocol if it helped allow relaying */
				memcpy(protocol + l, "\n (cert ", 7);
				memcpy(protocol + l + 7, email.s, email.len);
				protocol[l + 7 + email.len] = ')';
				protocol[l + 8 + email.len] = '\0';
				relayclient = 1;
			}
		}

		X509_free(peercert);
	} while (0);
	free(clients);
	free(clientbuf);

	/* we are not going to need this anymore: free the memory */
	SSL_set_client_CA_list(ssl, NULL);
	SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

	return relayclient;
}

int tls_init()
{
	SSL *myssl;
	SSL_CTX *ctx;
	const char *ciphers, *prot;
	string saciphers;
	unsigned int l;
	X509_STORE *store;
	X509_LOOKUP *lookup;
	char *newprot;

	SSL_library_init();
	STREMPTY(saciphers);

	/* a new SSL context with the bare minimum of options */
	ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx) {
		tls_err("unable to initialize ctx");
		return EDONE;
	}

	if (!SSL_CTX_use_certificate_chain_file(ctx, SERVERCERT)) {
		SSL_CTX_free(ctx);
		tls_err("missing certificate");
		return EDONE;
	}
	SSL_CTX_load_verify_locations(ctx, CLIENTCA, NULL);

#if OPENSSL_VERSION_NUMBER >= 0x00907000L
	/* crl checking */
	store = SSL_CTX_get_cert_store(ctx);
	if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) &&
				(X509_load_crl_file(lookup, CLIENTCRL, X509_FILETYPE_PEM) == 1))
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
						X509_V_FLAG_CRL_CHECK_ALL);
#endif

	/* set the callback here; SSL_set_verify didn't work before 0.9.6c */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	/* a new SSL object, with the rest added to it directly to avoid copying */
	myssl = SSL_new(ctx);
	SSL_CTX_free(ctx);
	if (!myssl) {
		tls_err("unable to initialize ssl");
		return EDONE;
	}

	/* this will also check whether public and private keys match */
	if (!SSL_use_RSAPrivateKey_file(myssl, SERVERCERT, SSL_FILETYPE_PEM)) {
		SSL_free(myssl);
		tls_err("no valid RSA private key");
		return EDONE;
	}

	ciphers = getenv("TLSCIPHERS");
	if (!ciphers) {
		const char *ciphfn = "control/tlsserverciphers";
		int e = lloadfilefd(open(ciphfn, O_RDONLY), &(saciphers.s), 1);

		if ((e < 0) && (errno != ENOENT)) {
			e = errno;

			SSL_free(myssl);
			err_control(ciphfn);
			errno = e;
			return -1;
		}
		if ( e >= 0) {
			saciphers.len = e;
			if (saciphers.len) {
				/* convert all '\0's except the last one to ':' */
				unsigned int i;

				for (i = 0; i < saciphers.len - 1; ++i)
					if (!saciphers.s[i])
						saciphers.s[i] = ':';
				ciphers = saciphers.s;
			}
		}
	}
	if (!ciphers || !*ciphers) ciphers = "DEFAULT";
	SSL_set_cipher_list(myssl, ciphers);
	free(saciphers.s);

	SSL_set_tmp_rsa_callback(myssl, tmp_rsa_cb);
	SSL_set_tmp_dh_callback(myssl, tmp_dh_cb);
	SSL_set_rfd(myssl, ssl_rfd = 0);
	SSL_set_wfd(myssl, ssl_wfd = 1);

	if (netwrite("220 ready for tls\r\n"))
		return errno;

	/* can't set ssl earlier, else netwrite above would try to send the data encrypted with the unfinished ssl */
	ssl = myssl;
	if (ssl_timeoutaccept(timeout) <= 0) {
		/* neither cleartext nor any other response here is part of a standard */
		const char *err = ssl_strerror();

		ssl_free(ssl);
		ssl = NULL;
		tls_out("connection failed", err);
		return EDONE;
	}

	prot = SSL_get_cipher(myssl);
	l = strlen(prot);
	newprot = realloc(protocol, l + 19);
	if (!newprot) {
		SSL_free(ssl);
		ssl = NULL;
		return ENOMEM;
	}
	protocol = newprot;
	/* populate the protocol string, used in Received */
	protocol[0] = '(';
	memcpy(protocol + 1, prot, l);
	l++;
	memcpy(protocol + l, " encrypted) ESMTP", 17);
	protocol[l + 17] = '\0';

	/* have to discard the pre-STARTTLS HELO/EHLO argument, if any */
	return 0;
}
