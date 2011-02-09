#ifndef _TESTCASE_IO_H
#define _TESTCASE_IO_H

#include <sys/types.h>
#include <openssl/ssl.h>

#define DECLARE_TC_SETUP(a) \
	extern void testcase_setup_##a(func_##a *f); \
	extern void testcase_ignore_##a()

typedef int (func_net_read)(void);
DECLARE_TC_SETUP(net_read);

typedef int (func_net_writen)(const char *const *);
DECLARE_TC_SETUP(net_writen);

typedef int (func_netwrite)(const char *);
DECLARE_TC_SETUP(netwrite);

typedef int (func_netnwrite)(const char *, const size_t);
DECLARE_TC_SETUP(netnwrite);

typedef size_t (func_net_readbin)(size_t, char *);
DECLARE_TC_SETUP(net_readbin);

typedef size_t (func_net_readline)(size_t, char *);
DECLARE_TC_SETUP(net_readline);

typedef int (func_data_pending)(void);
DECLARE_TC_SETUP(data_pending);

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

#endif /* _TESTCASE_IO_P_H */
