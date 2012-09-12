/** \file ipme.h
 \brief headers of functions to filter out IP addresses of the local machine
 */
#ifndef IPME_H
#define IPME_H

struct ips;

extern struct ips *filter_my_ips(struct ips *ipl) __attribute__ ((nonnull (1)));

#endif
