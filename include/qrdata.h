#ifndef QRDATA_H
#define QRDATA_H

#include <sys/types.h>

#ifdef __dietlibc__

typedef off_t q_off_t;

#else

#ifndef __USE_FILE_OFFSET64
typedef __off_t q_off_t;
#else
typedef __off64_t q_off_t;
#endif

#endif

extern const char *successmsg[];

extern int need_recode(const char *, q_off_t);
extern void send_data(void);
extern void send_bdat(void);

extern const char *msgdata;
extern q_off_t msgsize;
extern int ascii;

#endif
