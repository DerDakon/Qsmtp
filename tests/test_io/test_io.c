#include "testcase_io.h"
#include "testcase_io_p.h"

#define TC_SETUP(a) \
	func_##a *testcase_##a; \
	void testcase_setup_##a(func_##a *f) \
	{ \
		testcase_##a = f; \
	} \
	void testcase_ignore_##a() \
	{ \
		testcase_setup_##a(tc_ignore_##a); \
	}

TC_SETUP(net_read);
TC_SETUP(net_writen);
TC_SETUP(netwrite);
TC_SETUP(netnwrite);
TC_SETUP(net_readbin);
TC_SETUP(net_readline);
TC_SETUP(data_pending);
TC_SETUP(net_conn_shutdown);

TC_SETUP(log_writen);
TC_SETUP(log_write);
TC_SETUP(dieerror);

TC_SETUP(ssl_free);
TC_SETUP(ssl_exit);
TC_SETUP(ssl_error);
TC_SETUP(ssl_strerror);

TC_SETUP(ask_dnsmx);
TC_SETUP(ask_dnsaaaa);
TC_SETUP(ask_dnsa);
TC_SETUP(ask_dnsname);
