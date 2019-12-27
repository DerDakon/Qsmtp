/** \file fmt.h
 \brief functions for output formatting
 */
#ifndef FMT_H
#define FMT_H

#include <stdint.h>

extern void ultostr(const unsigned long u, char *) __attribute__ ((nonnull (2)));

/** \def ULSTRLEN
 \brief length of the ascii representation of an unsigned long
 */
#if __WORDSIZE == 64
#define ULSTRLEN 21
#else
#define ULSTRLEN 11
#endif

#endif
