/** \file qrdata.h
 \brief function definitions for Qremote's handling of message bodies
 */
#ifndef QRDATA_H
#define QRDATA_H

#include <sys/types.h>

extern const char *successmsg[];

extern unsigned int need_recode(const char *, off_t);
extern void send_data(unsigned int recodeflag);
extern void send_bdat(unsigned int recodeflag);

extern const char *msgdata;
extern off_t msgsize;

#endif
