#ifndef _TESTCASE_IO_P_H
#define _TESTCASE_IO_P_H

#include "testcase_io.h"

#define DECLARE_TC_PTR(a) \
	extern func_##a *testcase_##a; \
	extern func_##a tc_ignore_##a

DECLARE_TC_PTR(net_read);
DECLARE_TC_PTR(net_writen);
DECLARE_TC_PTR(netwrite);
DECLARE_TC_PTR(netnwrite);
DECLARE_TC_PTR(net_readbin);
DECLARE_TC_PTR(net_readline);
DECLARE_TC_PTR(data_pending);

DECLARE_TC_PTR(log_writen);
DECLARE_TC_PTR(log_write);
DECLARE_TC_PTR(dieerror);

DECLARE_TC_PTR(ssl_free);
DECLARE_TC_PTR(ssl_exit);
DECLARE_TC_PTR(ssl_error);
DECLARE_TC_PTR(ssl_strerror);

#endif /* _TESTCASE_IO_P_H */
