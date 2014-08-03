#ifndef _TESTCASE_IO_H
#define _TESTCASE_IO_H

#include <sys/types.h>
#include <openssl/ssl.h>

#include "netio.h"

#define TESTIO_MAX_LINELEN 1002

#define DECLARE_TC_SETUP(a) \
	extern void testcase_setup_##a(func_##a *f); \
	extern void testcase_ignore_##a()

struct ips;
struct in6_addr;

typedef int (func_net_read)(void);
DECLARE_TC_SETUP(net_read);

typedef int (func_net_writen)(const char *const *);
DECLARE_TC_SETUP(net_writen);

/**
 * @brief simple helper for net_writen()
 *
 * This function may be passed to testcase_setup_net_writen() to combine all
 * strings given in msg into a single string. The combined string is afterwards
 * passed to netnwrite() where it can be checked e.g. using
 * testcase_netnwrite_compare().
 */
extern int testcase_net_writen_combine(const char *const *msg);

typedef int (func_net_write_multiline)(const char *const *);
DECLARE_TC_SETUP(net_write_multiline);

typedef int (func_netnwrite)(const char *, const size_t);
DECLARE_TC_SETUP(netnwrite);

extern const char *netnwrite_msg; /**< the next message expected in netnwrite() */
/**
 * @brief a simple checker for netnwrite()
 *
 * This function may be passed to testcase_setup_netnwrite() to have a simple
 * checker for netnwrite(). The message sent to netnwrite() is compared to
 * netnwrite_msg. netnwrite_msg is reset afterwards. If the messages do not
 * match the program is aborted.
 */
extern int testcase_netnwrite_compare(const char *a, const size_t len);

typedef size_t (func_net_readbin)(size_t, char *);
DECLARE_TC_SETUP(net_readbin);

typedef size_t (func_net_readline)(size_t, char *);
DECLARE_TC_SETUP(net_readline);

typedef int (func_data_pending)(void);
DECLARE_TC_SETUP(data_pending);

typedef void (func_net_conn_shutdown)(const enum conn_shutdown_type);
DECLARE_TC_SETUP(net_conn_shutdown);

typedef void (func_log_writen)(int priority, const char **s);
DECLARE_TC_SETUP(log_writen);

typedef void (func_log_write)(int priority, const char *s);
DECLARE_TC_SETUP(log_write);

typedef void (func_dieerror)(int error);
DECLARE_TC_SETUP(dieerror);

typedef void (func_ssl_free)(SSL *myssl);
DECLARE_TC_SETUP(ssl_free);

typedef void (func_ssl_exit)(int status);
DECLARE_TC_SETUP(ssl_exit);

typedef const char *(func_ssl_error)(void);
DECLARE_TC_SETUP(ssl_error);

typedef const char *(func_ssl_strerror)(void);
DECLARE_TC_SETUP(ssl_strerror);

typedef int (func_ask_dnsmx)(const char *, struct ips **);
DECLARE_TC_SETUP(ask_dnsmx);

typedef int (func_ask_dnsaaaa)(const char *, struct in6_addr **);
DECLARE_TC_SETUP(ask_dnsaaaa);

typedef int (func_ask_dnsa)(const char *, struct in6_addr **);
DECLARE_TC_SETUP(ask_dnsa);

typedef int (func_ask_dnsname)(const struct in6_addr *, char **);
DECLARE_TC_SETUP(ask_dnsname);

#endif /* _TESTCASE_IO_P_H */
