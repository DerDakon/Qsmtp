/** \file starttlsr.h
 \brief interface for Qremote's STARTTLS handling
 */
#ifndef STARTTLSR_H
#define STARTTLSR_H

extern int tls_init(void);

extern const char *clientcertname;	/**< filename of the TLS client certificate */

#endif
