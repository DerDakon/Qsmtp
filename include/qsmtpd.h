#ifndef QSMTPD_H
#define QSMTPD_H
#include <netinet/in.h>
#include <sys/queue.h>
#include "sstring.h"
#include "dns.h"

struct xmitstat {			/* This contains some flags describing the transmission and it's status.
					 * This can be passed to the usercallbacks */
	unsigned int esmtp:1;		/* if we are using ESMTP extensions */
	unsigned int check2822:2;	/* if or not to check the message to strict compliance to RfC 2822 */
	unsigned int helostatus:3;	/* status of the given HELO/EHLO, see antispam.h for the meaning */
	unsigned int spf:4;		/* result of the SPF lookup */
	int fromdomain:3;		/* result of the lookup for fromips */
	unsigned int ipv4conn:1;	/* if this connection is made from a real IPv6 address or not */
	unsigned long thisbytes;	/* size of the message announced by the remote host */
	string mailfrom;		/* the current from address */
	string authname;		/* if SMTP AUTH is used (and successful) this is set */
	char *tlsclient;		/* TLS client authenticated by certificate for relaying */
	string remotehost;		/* the reverse lookup of the remote host */
	char *remoteip;			/* ip of the remote host as set in the environment */
	char *remoteinfo;		/* info gathered by tcpserver like remote username */
	string helostr;			/* the helo string sent by the client if different from the reverse lookup
					 * if the helo is identical to remotehost this is {NULL, 0} */
	struct in6_addr sremoteip;	/* parsed remoteip */
	struct ips *frommx;		/* MX IPs of from domain */
	char *spfexp;			/* the SPF explanation if provided by the domain or NULL if none */
};

extern struct xmitstat xmitstat;
extern char *protocol;
extern char *auth_host;			/* hostname for auth */
extern char *auth_check;		/* checkpassword or one of his friends for auth */
extern char **auth_sub;			/* subprogram and arguments to be invoked by auth_check (usually /bin/true) */
extern string heloname;			/* the fqdn to show in helo */

extern int err_control(const char *);

#define EBOGUS 1002
#define EDONE 1003

TAILQ_HEAD(tailhead, recip) head;
extern struct tailhead *headp;		/* List head. */

typedef struct recip {
	TAILQ_ENTRY(recip) entries;	/* List. */
	string to;			/* the mail address */
	int ok;				/* if this address is accepted or not */
} recip;

extern struct recip *thisrecip;

#endif
