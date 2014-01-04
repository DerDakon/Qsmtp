/** \file qsauth.h
 \brief function definitions for Qsmtpd's handling of message bodies
 */
#ifndef QSAUTH_H
#define QSAUTH_H

extern int smtp_auth(void);
extern char *smtp_authstring(void);

extern int auth_permitted(void);
extern void auth_setup(int argc, char **argv);

extern const char *auth_host;		/**< hostname for auth */
extern const char *auth_check;		/**< checkpassword or one of his friends for auth */
extern const char **auth_sub;		/**< subprogram and arguments to be invoked by auth_check (usually /bin/true) */

#endif
