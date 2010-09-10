/** \file qsmtpd.h
 \brief definitions for common parts from Qsmtpd exported from qsmtpd.c
 */
#ifndef QSMTPD_H
#define QSMTPD_H
#include <netinet/in.h>
#include <sys/queue.h>
#include <sys/types.h>
#include "sstring.h"
#include "qdns.h"

/*! \struct smtpcomm
 Describes a single SMTP command and it's transitions in the SMTP state machine.
 */
struct smtpcomm {
	char		*name;		/**< the SMTP command verb */
	int		len;		/**< strlen(name) */
	long		mask;		/**< the bitmask of states from where this is allowed */
	int		(*func)(void);	/**< the function that handles this command */
	long		state;		/**< the state to change to. If <0 don't change the state, if 0 use auto state */
	unsigned int	flags;		/**< bit 1: this command takes arguments
					     bit 2: this command allows lines > 512 chars (and will check this itself) */
};

/*! \struct xmitstat
 This contains some flags describing the transmission and it's status.
 This is used e.g. by the user filters.
 */
struct xmitstat {
	unsigned int esmtp:1;		/**< if we are using ESMTP extensions */
	unsigned int ipv4conn:1;	/**< if this connection is made from a real IPv6 address or not */
	unsigned int check2822:2;	/**< if or not to check the message to strict compliance to RfC 2822 */
	unsigned int helostatus:3;	/**< status of the given HELO/EHLO, see antispam.h for the meaning */
	unsigned int datatype:1;	/**< the datatype announced by the client (7BIT or 8BITMIME) */
	unsigned int spf:4;		/**< result of the SPF lookup */
	int fromdomain:3;		/**< result of the lookup for fromips */
	unsigned int spacebug:1;	/**< if client sends spaces between ':' and '<' */
	unsigned long thisbytes;	/**< size of the message announced by the remote host */
	string mailfrom;		/**< the current from address */
	string authname;		/**< if SMTP AUTH is used (and successful) this is set */
	char *tlsclient;		/**< TLS client authenticated by certificate for relaying */
	string remotehost;		/**< the reverse lookup of the remote host */
	char remoteip[INET6_ADDRSTRLEN];/**< ip of the remote host as set in the environment */
	char *remoteinfo;		/**< info gathered by tcpserver like remote username */
	string helostr;			/**< the helo string sent by the client if different from the reverse lookup
					 * if the helo is identical to remotehost this is {NULL, 0} */
	struct in6_addr sremoteip;	/**< parsed remote ip */
	char localip[INET6_ADDRSTRLEN]; /**< ip of local socket. If ipv4conn in IPv4 form! */
	struct in6_addr slocalip;	/**< parsed local ip */
	struct ips *frommx;		/**< MX IPs of from domain */
	char *spfexp;			/**< the SPF explanation if provided by the domain or NULL if none */
};

extern struct smtpcomm commands[];	/**< all supported SMTP commands */

extern struct xmitstat xmitstat;
extern char *protocol;
extern char *auth_host;			/**< hostname for auth */
extern char *auth_check;		/**< checkpassword or one of his friends for auth */
extern char **auth_sub;			/**< subprogram and arguments to be invoked by auth_check (usually /bin/true) */
extern string heloname;			/**< the fqdn to show in helo */
extern string liphost;			/**< replacement domain if to address is <foo@[ip]> */
extern unsigned int goodrcpt;		/**< number of valid recipients */
extern int badbounce;			/**< bounce message with more than one recipient */
extern unsigned long sslauth;		/**< if SMTP AUTH is only allowed after STARTTLS */
extern unsigned long databytes;		/**< maximum message size */
extern int relayclient;			/**< flag if this client is allowed to relay by IP: 0 unchecked, 1 allowed, 2 denied */
extern long comstate;			/**< status of the command state machine */
extern int authhide;			/**< hide source of authenticated mail */

extern int err_control(const char *);
extern void freedata(void);
extern int hasinput(void);
extern pid_t fork_clean();

#define EBOGUS 1002
#define EDONE 1003

TAILQ_HEAD(tailhead, recip) head;

/** \struct recip
 \brief list of recipients given for this transaction
 
 All mail addresses given as recipients for the current mail transfer are stored in
 this list, regardless if they are accepted or not. If there are more recipients given
 then permitted by MAXRCPT they will be _not_ stored here, every following one will be
 rejected with a temporary error anyway. Receipients that rejected the mail basing on
 their spam filter rules are stored here so cb_badcc() can take them into account.
 */
struct recip {
	TAILQ_ENTRY(recip) entries;	/**< List. */
	string to;			/**< the mail address */
	int ok;				/**< if this address is accepted or not */
};

extern struct recip *thisrecip;

#define HELOSTR (xmitstat.helostr.len ? xmitstat.helostr.s : xmitstat.remotehost.s)
#define HELOLEN (xmitstat.helostr.len ? xmitstat.helostr.len : xmitstat.remotehost.len)

#define MAILFROM (xmitstat.mailfrom.len ? xmitstat.mailfrom.s : "")

#endif
