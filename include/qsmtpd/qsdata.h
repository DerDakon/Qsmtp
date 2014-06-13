/** \file qsdata.h
 \brief function definitions for Qsmtpd's handling of message bodies
 */
#ifndef QSDATA_H
#define QSDATA_H

#include <sys/types.h>

extern int smtp_data(void);
extern int smtp_bdat(void);

extern size_t maxbytes;

#endif
