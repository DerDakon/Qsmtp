#include "testcase_io.h"
#include "testcase_io_p.h"

#include <tls.h>

#include <stdlib.h>
#include <unistd.h>

SSL *ssl;

void
ssl_free(SSL *myssl)
{
	ASSERT_CALLBACK(testcase_ssl_free);

	testcase_ssl_free(myssl);
}

void
tc_ignore_ssl_free(SSL *myssl __attribute__((unused)))
{
}

const char *
ssl_error(void)
{
	ASSERT_CALLBACK(testcase_ssl_error);

	return testcase_ssl_error();
}

const char *
tc_ignore_ssl_error(void)
{
	return NULL;
}

const char *
ssl_strerror(void)
{
	ASSERT_CALLBACK(testcase_ssl_strerror);

	return testcase_ssl_strerror();
}

const char *
tc_ignore_ssl_strerror(void)
{
	return NULL;
}
