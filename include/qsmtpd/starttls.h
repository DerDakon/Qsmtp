/** \file starttls.h
 \brief functions for Qsmtpd STARTTLS functions
 */

#ifndef _QSMTPD_STARTTLS_H
#define _QSMTPD_STARTTLS_H 1

extern int smtp_starttls(void);
extern int tls_verify(void);

extern char certfilename[];		/**< path to SSL certificate filename */

#endif
