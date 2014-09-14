#include <control.h>
#include <diropen.h>
#include <log.h>
#include <netio.h>
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/starttls.h>
#include <ssl_timeoutio.h>
#include <tls.h>
#include <qremote/starttlsr.h>
#include <qremote/qremote.h>

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/wait.h>

struct xmitstat xmitstat;
char *partner_fqdn = "testcert.example.org";
char certfilename[] = "control/servercert.pem";
char *rhost;
int socketd;

int
checkaddr(const char *const a __attribute__((unused)))
{
	/* accept everything */
	return 0;
}

void
err_mem(const int doquit __attribute__ ((unused)))
{
	abort();
}

void
err_conf(const char *m __attribute__ ((unused)))
{
	abort();
}

void
log_writen(int priority __attribute__ ((unused)), const char **s __attribute__ ((unused)))
{
	abort();
}

void
log_write(int priority __attribute__ ((unused)), const char *s __attribute__ ((unused)))
{
	abort();
}

void
net_conn_shutdown(const enum conn_shutdown_type sd_type __attribute__ ((unused)))
{
	abort();
}

void
write_status(const char *str __attribute__ ((unused)))
{
	abort();
}

void
sync_pipelining(void)
{
}

int
err_control2(const char *a __attribute__ ((unused)), const char *b __attribute__ ((unused)))
{
	abort();
}

void
quitmsg(void)
{
	abort();
}

void
write_status_m(const char **strs __attribute__ ((unused)), const unsigned int count  __attribute__ ((unused)))
{
}

static int sockets[2];

static int
setup(void)
{
	sigset_t mask;

	controldir_fd = get_dirfd(AT_FDCWD, "control");

	if (controldir_fd < 0) {
		fprintf(stderr, "Cannot open control dir: %i\n", errno);
		return -1;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
		fprintf(stderr, "Cannot create socket pair: %i\n", errno);
		close(controldir_fd);
		return -1;
	}

	/* Block SIGPIPE, otherwise the process will get killed when the remote
	 * end cancels the connection improperly. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGPIPE);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		fprintf(stderr, "Cannot block SIGPIPE: %i\n", errno);

		close(controldir_fd);
		close(sockets[0]);
		close(sockets[1]);
		return -1;
	}

	close(0);
	timeout = 3;

	return 0;
}

static const char query[] = "ping";
static const char answer[] = "250 pong";

static int
client(void)
{
	int r, k;
	const char *ping[] = { query, NULL };

	close(sockets[0]);

	if (dup2(sockets[1], 0) != 0) {
		fprintf(stderr, "client: cannot move socket to fd 0: %i\n", errno);
		close(sockets[1]);
		return -1;
	}

	socketd = sockets[1];

	r = tls_init();
	if (r != 0)
		return r;

	printf("CLIENT: init done, cipher is %s\n", SSL_get_cipher(ssl));

	net_writen(ping);
	printf("CLIENT: sent ping\n");
	k = netget(0);
	if (k != 250) {
		fprintf(stderr, "client: netget() returned wrong result %i\n", k);
		r++;
	} else if ((linein.len != strlen(answer) || strcmp(linein.s, answer) != 0)) {
		fprintf(stderr, "client: netget() returned string '%s' instead of '%s'\n", linein.s, answer);
		r++;
	}

	return r;
}

static int expect_verify_success;

static int
server(void)
{
	int r;
	char buf[16];
	const char stls[] = "STARTTLS\r\n";

	close(sockets[1]);

	if (dup2(sockets[0], 0) != 0) {
		fprintf(stderr, "server: cannot move socket to fd 0: %i\n", errno);
		return -1;
	}

	socketd = sockets[0];

	memset(buf, 0, sizeof(buf));
	if ((read(socketd, buf, sizeof(buf)) != strlen(stls)) || (strcmp(buf, stls) != 0)) {
		buf[sizeof(buf) - 1] = '\0';
		fprintf(stderr, "server: did not receive STARTTLS command, but '%s'\n", buf);
		close(socketd);
		return 1;
	}

	xmitstat.esmtp = 1;
	r = smtp_starttls();

	if (r != 0)
		return r;

	printf("SERVER: init done, cipher is %s\n", SSL_get_cipher(ssl));

	if (net_read(0) != 0) {
		fprintf(stderr, "server: net_read() failed\n");
		r++;
	} else if ((linein.len != strlen(query) || strcmp(linein.s, query) != 0)) {
		fprintf(stderr, "server: net_read() returned string '%s' instead of '%s'\n", linein.s, query);
		r++;
	} else {
		const char *pong[] = { answer, NULL };
		int v;

		printf("SERVER: got ping\n");

		v = tls_verify();
		printf("SERVER: verify returned %i\n", v);
		if (v != expect_verify_success)
			r++;

		net_writen(pong);
	}

	return r;
}

int
main(int argc, char **argv)
{
	pid_t child;
	int r;

	while ((r = getopt(argc, argv, "s:")) != -1) {
		switch(r) {
		case 's':
			if (strcmp(optarg, "EISDIR") == 0) {
				expect_verify_success = -EISDIR;
			} else {
				char *endp;
				unsigned long l = strtoul(optarg, &endp, 10);

				if ((*endp != '\0') || (l == 0) || (l >= INT_MAX)) {
					fprintf(stderr, "bad value: %s\n", optarg);
					return 1;
				}
			}
			break;
		case ':':
			printf("-%c without argument\n", optopt);
			return 1;
		case '?':
			printf("unknown arg %c\n", optopt);
			return 1;
		}
	}

	if (setup())
		return 1;

	child = fork();
	if (child < 0) {
		puts("fork() failed");
		r = errno;
	} else if (child == 0) {
		r = client();
	} else {
		int s = -1; /* to keep valgrind silent */
		r = server();
		waitpid(child, &s, 0);
		if (!WIFEXITED(s) || (WEXITSTATUS(s) != 0))
			r++;
	}

	close(controldir_fd);
	if (ssl)
		ssl_free(ssl);
	close(socketd);
	close(0);

	return r;
}
