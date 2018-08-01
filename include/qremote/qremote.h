/** \file qremote.h
 \brief definitions for common parts from Qremote exported from qremote.c
 */
#ifndef QREMOTE_H
#define QREMOTE_H 1

#include "sstring.h"

#include <netinet/in.h>

struct ips;

extern void err_mem(const int) __attribute__ ((noreturn));
extern void err_conf(const char *) __attribute__ ((noreturn)) __attribute__ ((nonnull (1)));
extern void err_confn(const char **, void *) __attribute__ ((noreturn)) __attribute__ ((nonnull (1)));

extern void remote_common_setup(void);

/**
 * @brief get one line from the network
 * @param terminate if the program should be terminated on errors
 * @return SMTP return code of the message or negative error code
 * @retval -EINVAL the server send a reply that was syntactically invalid
 *
 * If an out of memory condition occurs the program will be terminated regardless of
 * the terminate parameter.
 *
 * If an error occurs and terminate is not set the connection will be shut down
 * before the function returns unless the return code is -EINVAL.
 */
extern int netget(const unsigned int terminate);

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

/**
 * @brief write status messages to qmail-rspawn
 * @param strs the strings to write
 * @param count how many strings to write
 */
extern void write_status_raw_m(const char **strs, const unsigned int count) __attribute__ ((nonnull (1)));

/**
 * @brief send the SMTP envelope
 * @param recodeflag the 8bit status of the mail as returned by need_recode()
 * @param sender envelope sender address
 * @param rcptcount the number of recipients in rcpts
 * @param rcpts the recipients
 * @return if all recipients were rejected
 * @retval 1 all recipients were rejected, mail must not be sent
 * @retval 0 at least one recipient was accepted, send mail
 */
extern int send_envelope(const unsigned int recodeflag, const char *sender, int rcptcount, char **rcpts);

extern char *rhost;
extern size_t rhostlen;
extern char *partner_fqdn;
extern unsigned int smtpext;
extern string heloname;
#ifdef CHUNKING
extern size_t chunksize;
#endif
extern char *clientcertbuf;
extern struct in6_addr outgoingip;
extern struct in6_addr outgoingip6;

struct ips *smtproute(const char *, const size_t, unsigned int *);
void quitmsg(void);

#define EDONE 1003

#endif
