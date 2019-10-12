/** \file qrdata.h
 \brief function definitions for Qremote's handling of message bodies
 */
#ifndef QRDATA_H
#define QRDATA_H

#include <sys/types.h>

extern const char *successmsg[];

enum recode_reasons {
	recode_8bit = 0x1,	/**< buffer has 8bit characters */
	recode_long_line = 0x2,	/**< buffer contains line longer 998 chars */
	recode_qp_body = recode_8bit | recode_long_line,	/**< body part needs recoding to qp */
	recode_long_header = 0x4,	/**< header contains line longer 998 chars */
	recode_long = recode_long_line | recode_long_header,	/**< line length would violate SMTP limits */
	recode_END
};

extern unsigned int need_recode(const char *, off_t);
extern void send_data(unsigned int recodeflag);
extern void send_bdat(unsigned int recodeflag);

extern const char *msgdata;
extern off_t msgsize;

#endif
