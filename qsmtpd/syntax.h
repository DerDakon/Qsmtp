/** \file syntax.h
 * \brief functions to handle syntax error in the commands an SMTP client sends
 */
#ifndef SYNTAX_H
#define SYNTAX_H

extern int badcmds;			/**< bad commands in a row */

extern int hasinput(const int quitloop);
extern void check_max_bad_commands(void);
extern void sync_pipelining(void);
void __attribute__ ((noreturn)) wait_for_quit(void);

#endif /* SYNTAX_H */
