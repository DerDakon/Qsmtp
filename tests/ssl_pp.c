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
static const char *logmsg;
static const char *client_log;
static const char *server_log;
static int client_init_result;
static int is_client;

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
log_writen(int priority, const char **s)
{
	unsigned int pos = 0;
	size_t off = 0;

	if (is_client)
		printf("CLIENT: log(%i, ", priority);
	else
		printf("SERVER: log(%i, ", priority);

	while (s[pos] != NULL)
		printf("%s", s[pos++]);
	printf(")\n");

	if (logmsg == NULL)
		abort();

	pos = 0;

	while (s[pos] != NULL) {
		const size_t l = strlen(s[pos]);
		if (strncmp(logmsg + off, s[pos], l) != 0)
			abort();
		off += l;
		pos++;
	}

	if (logmsg[off] != '\0')
		abort();
}

void
log_write(int priority, const char *s)
{
	const char *msg[] = { s, NULL };
	log_writen(priority, msg);
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
	sigset_t mask;
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
	timeout = 20;

	return 0;
}

static const char query[] = "ping";
static const char answer[] = "250 pong";

static int
client(void)
{
	const char *ping[] = { query, NULL };

	is_client = 1;

	close(sockets[0]);

	if (dup2(sockets[1], 0) != 0) {
		fprintf(stderr, "client: cannot move socket to fd 0: %i\n", errno);
		close(sockets[1]);
		return -1;
	}

	socketd = sockets[1];

	int r = tls_init();
	if (r != client_init_result)
		return 1;

	r = 0;
	printf("CLIENT: init done, cipher is %s\n", SSL_get_cipher(ssl));

	net_writen(ping);
	printf("CLIENT: sent ping\n");
	int k = netget(0);
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
	char buf[16];
	const char stls[] = "STARTTLS\r\n";

	close(sockets[1]);

	if (dup2(sockets[0], 0) != 0) {
		fprintf(stderr, "server: cannot move socket to fd 0: %i\n", errno);
		return -1;
	}

	socketd = sockets[0];

	memset(buf, 0, sizeof(buf));
	if ((read(socketd, buf, sizeof(buf)) != (ssize_t)strlen(stls)) || (strcmp(buf, stls) != 0)) {
		buf[sizeof(buf) - 1] = '\0';
		fprintf(stderr, "server: did not receive STARTTLS command, but '%s'\n", buf);
		close(socketd);
		return 1;
	}

	xmitstat.esmtp = 1;
	int r = smtp_starttls();

	if (r != 0)
		return r;

	printf("SERVER: init done, cipher is %s\n", SSL_get_cipher(ssl));

	r = smtp_starttls();
	if (r != 1) {
		fprintf(stderr, "SERVER: second call to smtp_starttls() did not return 1, but %i\n", r);
		r = 1;
	} else {
		r = 0;
	}

	if (net_read(0) != 0) {
		fprintf(stderr, "server: net_read() failed\n");
		r++;
	} else if ((linein.len != strlen(query) || strcmp(linein.s, query) != 0)) {
		fprintf(stderr, "server: net_read() returned string '%s' instead of '%s'\n", linein.s, query);
		r++;
	} else {
		const char *pong[] = { answer, NULL };

		printf("SERVER: got ping\n");

		const int v = tls_verify();
		printf("SERVER: verify returned %i, expected %i\n", v, expect_verify_success);
		if (v != expect_verify_success)
			r++;
		if (v == 1) {
			printf("SERVER: TLS client was identified as %s\n", xmitstat.tlsclient);
			free(xmitstat.tlsclient);
		}

		net_writen(pong);
	}

	return r;
}

int
main(int argc, char **argv)
{
	int r;

	while ((r = getopt(argc, argv, "s:f:l:L:i:")) != -1) {
		switch(r) {
		case 's':
			/* result of server tls_verify() */
			if (strcmp(optarg, "EISDIR") == 0) {
				expect_verify_success = -EISDIR;
			} else {
				char *endp;
				unsigned long l = strtoul(optarg, &endp, 10);

				if ((*endp != '\0') || (l == 0) || (l >= INT_MAX)) {
					fprintf(stderr, "bad value: %s\n", optarg);
					return 1;
				}
				expect_verify_success = l;
			}
			break;
		case 'f':
			/* value for partner_fqdn */
			partner_fqdn = optarg;
			break;
		case 'l':
			/* expected client log message */
			client_log = optarg;
			break;
		case 'L':
			/* expected server log message */
			server_log = optarg;
			break;
		case 'i':
			/* expected return value of client tls_init() */
			if (strcmp(optarg, "EDONE") == 0) {
				client_init_result = EDONE;
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

	const pid_t child = fork();
	if (child < 0) {
		puts("fork() failed");
		r = errno;
	} else if (child == 0) {
		logmsg = client_log;
		rhost = partner_fqdn;
		r = client();
	} else {
		int s = -1; /* to keep valgrind silent */
		logmsg = server_log;
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
