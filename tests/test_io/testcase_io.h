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

typedef int (func_net_read)(const int);
DECLARE_TC_SETUP(net_read);

extern const char *net_read_msg;	/**< the message that will be used the next time net_read() is called */
extern int net_read_fatal;	/**< the value of the fatal parameter that is expected on the next call to net_read() */
/**
 * @brief a simple checker for net_read
 *
 * This function may be passed to testcase_setup_net_read() to have a simple
 * checker for net_read(). If net_read_msg is set it's contents are passed to
 * the caller and net_read_msg is reset. Otherwise the program is aborted.
 *
 * If net_read_msg is a value smaller than 4096 then no string will be
 * returned, but errno will be set to the value cast to an int and -1 is
 * returned.
 */
extern int testcase_net_read_simple(const int fatal);

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

/**
 * @brief check if netnwrite() was called
 * @param prefix text to print before the error message
 * @returns if netnwrite() was called
 * @retval 0 netnwrite() was called, i.e. netnwrite_msg is NULL
 * @retval 1 netnwrite() was not called, i.e. netnwrite_msg != NULL
 *
 * This is a simple checker to see if expected calls to netnwrite() arrived,
 * use it like:
 *
 * @code
 * err += testcase_netnwrite_check("my fancy test");
 * @endcode
 *
 * netnwrite_msg is always NULL once this function returns.
 */
extern int testcase_netnwrite_check(const char *prefix);

/**
 * @brief simulate the native behavior of net_write_multiline()
 *
 * This function is a copy of the real net_write_multiline() function. It will
 * combine it's input and pass it on to netnwrite() as the original function
 * does. In contrast it has no fallback mechanism on memory shortage, instead
 * it will just terminate the program with an error code.
 */
extern int testcase_native_net_write_multiline(const char *const *s);

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

/**
 * @brief simple helper for log_writen()
 *
 * This function may be passed to testcase_setup_log_writen() to combine all
 * strings given in msg into a single string. The combined string is afterwards
 * passed to log_write() where it can be checked e.g. using
 * testcase_log_write_compare().
 */
extern void testcase_log_writen_combine(int priority, const char **msg);

/**
 * @brief redirect helper for log_writen()
 *
 * This function may be passed to testcase_setup_log_writen() to redirect
 * all log messages to stdout.
 */
extern void testcase_log_writen_console(int priority, const char **msg);

typedef void (func_log_write)(int priority, const char *s);
DECLARE_TC_SETUP(log_write);

extern const char *log_write_msg;	/**< the next message expected in log_write() */
extern int log_write_priority;		/**< the priority of the next message in log_write() */

/**
 * @brief a simple checker for log_write()
 *
 * This function may be passed to testcase_setup_log_write() to have a simple
 * checker for log_write(). The message sent to log_write() is compared to
 * log_write_msg and log_write_priority. log_write_msg is reset afterwards.
 * If the messages do not match the program is aborted.
 */
extern void testcase_log_write_compare(int priority, const char *a);

typedef void (func_ssl_free)(SSL *myssl);
DECLARE_TC_SETUP(ssl_free);

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
