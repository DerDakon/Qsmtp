/** \file log.h
 \brief header for syslog interface functions
 */
#ifndef LOG_H
#define LOG_H

extern void log_writen(int priority, const char **);
extern inline void log_write(int priority, const char *);
/* this function has to be implemented by every program */
extern void dieerror(int error) __attribute__ ((noreturn));

#endif
