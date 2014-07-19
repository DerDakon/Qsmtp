/** \file conn.h
 \brief headers of Qremote functions for connection establishing
 */
#ifndef CONN_H
#define CONN_H

#include <qdns.h>

#include <netinet/in.h>

extern unsigned int targetport;	/**< the port on the destination host to connect to */

extern int tryconn(struct ips *mx, const struct in6_addr *outip4, const struct in6_addr *outip6);

/**
 * @brief establish a connection to a MX
 * @param mx list of MX ips
 * @param outip4 address to use when making outgoing IPv4 connections
 * @param outip6 address to use when making outgoing IPv6 connections
 *
 * This will return once a connection to a remote host has been successfully
 * established and the greeting of the remote server has been parsed. If no
 * connection can be made this function will not return.
 */
extern void connect_mx(struct ips *mx, const struct in6_addr *outip4, const struct in6_addr *outip6);
extern void getmxlist(char *, struct ips **);

#endif
