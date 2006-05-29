/** \file xtext.h
 \brief headers of functions for xtext parsing
 */
#ifndef QSMTP_XTEXT_H
#define QSMTP_XTEXT_H

#include <sys/types.h>

ssize_t xtextlen(const char *) __attribute__ ((pure)) __attribute__ ((nonnull (1)));

#endif
