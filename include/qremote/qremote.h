/** \file qremote.h
 \brief definitions for common parts from Qremote exported from qremote.c
 */
#ifndef QREMOTE_H
#define QREMOTE_H 1

#include "sstring.h"

extern void err_mem(const int) __attribute__ ((noreturn));
extern void err_conf(const char *) __attribute__ ((noreturn)) __attribute__ ((nonnull (1)));
extern void err_confn(const char **, void *) __attribute__ ((noreturn)) __attribute__ ((nonnull (1)));
extern int netget(void);

/**
 * @brief write raw status message to qmail-rspawn
 * @param str the data to write
 * @param len length of the data to write
 */
extern void write_status_raw(const char *str, const size_t len) __attribute__ ((nonnull (1)));

/**
 * @brief write status message to qmail-rspawn
 * @param str the string to write
 *
 * This will include the trailing 0-byte in the output as qmail-rspawn awaits
 * that as separator between the output fields.
 */
extern void write_status(const char *str) __attribute__ ((nonnull (1)));

/**
 * @brief write status messages to qmail-rspawn
 * @param strs the strings to write
 * @param count how many strings to write
 *
 * This will include the trailing 0-byte after the last entry in the output
 * as qmail-rspawn awaits that as separator between the output fields.
 */
extern void write_status_m(const char **strs, const unsigned int count) __attribute__ ((nonnull (1)));

extern char *rhost;
extern size_t rhostlen;
extern char *partner_fqdn;
extern unsigned int smtpext;
extern string heloname;
#ifdef CHUNKING
extern size_t chunksize;
#endif

struct ips *smtproute(const char *, const size_t, unsigned int *);
void quitmsg(void);

#define EDONE 1003

#endif
