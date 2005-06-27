#ifndef QOFF_H
#define QOFF_H

#ifdef __dietlibc__

typedef off_t q_off_t;

#else

#ifndef __USE_FILE_OFFSET64
typedef __off_t q_off_t;
#else
typedef __off64_t q_off_t;
#endif

#endif

#endif
