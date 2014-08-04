/** @file commands.h
 * @brief function definitions for SMTP command handler functions
 *
 * Handler functions may also be defined elsewhere, e.g. in qsdata.h.
 */
#ifndef QSMTPD_COMMANDS_H
#define QSMTPD_COMMANDS_H

#include <sys/types.h>

#define MAXRCPT		500		/**< maximum number of recipients in a single mail */

extern int smtp_noop(void);
extern int smtp_quit(void);
extern int smtp_rset(void);
extern int smtp_helo(void);
extern int smtp_ehlo(void);
extern int smtp_from(void);
extern int smtp_rcpt(void);
extern int smtp_vrfy(void);
extern int http_post(void);
extern int __attribute__ ((noreturn)) smtp_quit(void);

extern char *rcpthosts;			/**< memory mapping of control/rcpthosts */
extern off_t rcpthsize;			/**< sizeof("control/rcpthosts") */
extern unsigned int rcptcount;		/**< number of recipients in lists including rejected */

#endif /* QSMTPD_COMMANDS_H */
