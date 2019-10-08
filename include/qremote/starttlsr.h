/** \file starttlsr.h
 \brief interface for Qremote's STARTTLS handling
 */
#ifndef STARTTLSR_H
#define STARTTLSR_H

struct daneinfo;

extern int tls_init(const struct daneinfo *d, int cnt);

extern const char *clientcertname;	/**< filename of the TLS client certificate */

#endif
