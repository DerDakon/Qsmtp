/** \file qsauth.h
 \brief function definitions for Qsmtpd's handling of message bodies
 */
#ifndef QSAUTH_H
#define QSAUTH_H

extern int smtp_auth(void);
extern char *smtp_authstring(void);

#endif
