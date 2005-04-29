#ifndef QRDATA_H
#define QRDATA_H

#include <sys/types.h>

#ifndef __USE_FILE_OFFSET64
typedef __off_t q_off_t;
#else
typedef __off64_t q_off_t;
#endif

extern const char *successmsg[];

extern int scan_8bit(const char *, q_off_t);
extern void send_data(void);
extern void send_bdat(void);

extern const char *msgdata;
extern q_off_t msgsize;
extern int ascii;

#endif
