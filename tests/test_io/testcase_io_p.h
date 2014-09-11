#ifndef _TESTCASE_IO_P_H
#define _TESTCASE_IO_P_H

#include "testcase_io.h"

#include <qs_backtrace.h>

#include <assert.h>

#define DECLARE_TC_PTR(a) \
	extern func_##a *testcase_##a; \
	extern func_##a tc_ignore_##a

DECLARE_TC_PTR(net_read);
DECLARE_TC_PTR(net_writen);
DECLARE_TC_PTR(net_write_multiline);
DECLARE_TC_PTR(netnwrite);
DECLARE_TC_PTR(net_readbin);
DECLARE_TC_PTR(net_readline);
DECLARE_TC_PTR(data_pending);
DECLARE_TC_PTR(net_conn_shutdown);

DECLARE_TC_PTR(log_writen);
DECLARE_TC_PTR(log_write);

DECLARE_TC_PTR(ssl_free);
DECLARE_TC_PTR(ssl_error);
DECLARE_TC_PTR(ssl_strerror);

DECLARE_TC_PTR(ask_dnsmx);
DECLARE_TC_PTR(ask_dnsaaaa);
DECLARE_TC_PTR(ask_dnsa);
DECLARE_TC_PTR(ask_dnsname);

#define ASSERT_CALLBACK(a) \
	do { \
		if (a == NULL) \
			qs_backtrace(); \
		assert(a != NULL); \
	} while (0)

#endif /* _TESTCASE_IO_P_H */
