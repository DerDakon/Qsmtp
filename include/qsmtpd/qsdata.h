/** \file qsdata.h
 \brief function definitions for Qsmtpd's handling of message bodies
 */
#ifndef QSDATA_H
#define QSDATA_H

extern int smtp_data(void);
extern int smtp_bdat(void);
extern void queue_reset(void);

extern unsigned long maxbytes;

#endif
