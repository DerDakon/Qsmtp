/** @file client.h
 @brief definitions for SMTP client code to parse server replies
 */
#ifndef QREMOTE_CLIENT_H
#define QREMOTE_CLIENT_H 1

struct ips;

extern void getrhost(const struct ips *m, const unsigned short idx);
extern int checkreply(const char *status, const char **pre, const int mask);

#endif /* QREMOTE_CLIENT_H */
