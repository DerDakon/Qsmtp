#include <qremote/qremote.h>
#include <qremote/starttlsr.h>
#include <ssl_timeoutio.h>
#include <control.h>
#include <tls.h>

#include "test_io/testcase_io.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

char *rhost;
size_t rhostlen;
char *partner_fqdn;
unsigned int smtpext;
string heloname;
static unsigned int conf_error_expected;
static const char *netget_result = "421 ";
static int other_socket_end = -1;

void
err_conf(const char *errmsg)
{
	fputs("CONFIG error: ", stderr);
	fputs(errmsg, stderr);

	if (conf_error_expected)
		exit(0);
	else
		exit(EFAULT);
}

void
err_mem(const int k __attribute__((unused)))
{
	exit(ENOMEM);
}

void
write_status_raw(const char *str, const size_t len)
{
	(void) write(1, str, len);
}

void
write_status(const char *str)
{
	puts(str);
}

int
netget(const unsigned int terminate __attribute__ ((unused)))
{
	const char *s = strchr(netget_result, ';');
	size_t l;

	if (s == NULL)
		l = strlen(netget_result);
	else
		l = s - netget_result;

	assert(l == 4);

	snprintf(linein.s, TESTIO_MAX_LINELEN, "%.4s<content of linein>", netget_result);

	netget_result = s ? s + 1 : NULL;

	return strtoul(linein.s, NULL, 10);
}

void
write_status_m(const char **strs, const unsigned int count)
{
	for (unsigned int i = 0; i < count - 1; i++)
		fputs(strs[i], stdout);

	write_status(strs[count - 1]);
}

const char *
test_ssl_strerror(void)
{
	return "expected error case";
}

void
test_net_conn_shutdown(const enum conn_shutdown_type sd_type __attribute__((unused)))
{
	if (ssl != NULL)
		ssl_free(ssl);
	close(controldir_fd);
	if (socketd >= 0)
		close(socketd);
	if (other_socket_end >= 0)
		close(other_socket_end);
}

void
test_ssl_free(SSL *myssl)
{
	if (SSL_shutdown(myssl) == 0)
		SSL_shutdown(myssl);
	SSL_free(myssl);

	ssl_library_destroy();
}

void
ssl_library_destroy()
{
	ERR_remove_state(0);
	CONF_modules_unload(1);
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
}

const char *
test_ssl_error(void)
{
	return "expected SSL testcase error";
}

int
main(int argc, char **argv)
{
	/* Block SIGPIPE, otherwise the process will get killed when trying to
	 * read from a socket where the remote end was closed. */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGPIPE);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		int e = errno;
		fprintf(stderr, "Cannot block SIGPIPE, error %i\n", e);
		return e;
	}

	if (argc > 3) {
		fprintf(stderr, "Usage: %s [partner_fqdn [netget_result]]\n", argv[0]);
		return EINVAL;
	} else if (argc >= 2) {
		partner_fqdn = argv[1];
		rhost = partner_fqdn;
		if (strstr(partner_fqdn, "bad") != NULL)
			testcase_setup_ssl_error(test_ssl_error);
		if (strstr(partner_fqdn, "conferror.") != NULL)
			conf_error_expected = 1;
		if (argc > 2) {
			netget_result = argv[2];
			testcase_setup_ssl_strerror(test_ssl_strerror);
		}
	} else {
		rhost = "[192.0.2.4]";
	}
	rhostlen = strlen(rhost);

	controldir_fd = open("control", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	timeout = 1;

	netnwrite_msg = "STARTTLS\r\n";

	testcase_setup_netnwrite(testcase_netnwrite_compare);
	testcase_setup_ssl_free(test_ssl_free);
	testcase_setup_net_conn_shutdown(test_net_conn_shutdown);
	testcase_setup_log_writen(testcase_log_writen_console);

	if (strncmp(netget_result, "220", 3) == 0) {
		int sfd[2];

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sfd) != 0) {
			fprintf(stderr, "cannot create socket pair: %i\n", errno);
			return -1;
		}

		socketd = sfd[0];
		if (netget_result[3] == ' ')
			other_socket_end = sfd[1];
		else
			close(sfd[1]);
	}

	const int r = tls_init();

	test_net_conn_shutdown(shutdown_clean);

	switch (r) {
	case ETIMEDOUT:
		printf("RETURN VALUE: ETIMEDOUT\n");
		break;
	case EPIPE:
		printf("RETURN VALUE: EPIPE\n");
		break;
	default:
		printf("RETURN VALUE: %i\n", r);
	}

	return r;
}
