#ifndef LOG_H
#define LOG_H

extern const char *diemsg;

extern void log_writen(int priority, const char **);
extern inline void log_write(int priority, const char *);
extern void __attribute__ ((noreturn)) dieerror(int error);

#endif
