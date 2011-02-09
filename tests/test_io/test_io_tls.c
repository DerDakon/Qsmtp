#include "testcase_io.h"
#include "testcase_io_p.h"

#include <tls.h>

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

SSL *ssl;

void
ssl_free(SSL *myssl)
{
	assert(testcase_ssl_free != NULL);

	testcase_ssl_free(myssl);
}

void
tc_ignore_ssl_free(SSL *myssl __attribute__((unused)))
{
}

#undef _exit

void
ssl_exit(int status)
{
	assert(testcase_ssl_exit != NULL);

	testcase_ssl_exit(status);

	exit(status);
}

void
tc_ignore_ssl_exit(int status __attribute__((unused)))
{
}

const char *
ssl_error(void)
{
	assert(testcase_ssl_error != NULL);

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
	assert(testcase_ssl_strerror != NULL);

	return testcase_ssl_strerror();
}

const char *
tc_ignore_ssl_strerror(void)
{
	return NULL;
}
