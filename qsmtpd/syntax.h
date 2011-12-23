/** \file qsmtpd.h
 * \brief definitions for common parts from Qsmtpd exported from qsmtpd.c
 */
#ifndef SYNTAX_H
#define SYNTAX_H

extern int badcmds;			/**< bad commands in a row */

extern int hasinput(const int quitloop);
extern void check_max_bad_commands(void);
extern void sync_pipelining(void);
void __attribute__ ((noreturn)) wait_for_quit(void);

#endif /* SYNTAX_H */
