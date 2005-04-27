#ifndef QRDATA_H
#define QRDATA_H

#include <sys/types.h>

extern const char *successmsg[];

extern void send_data(void);
extern void send_bdat(void);

extern const char *msgdata;
#ifndef __USE_FILE_OFFSET64
extern __off_t msgsize;
#else
extern __off64_t msgsize;
#endif

extern int ascii;

#endif
