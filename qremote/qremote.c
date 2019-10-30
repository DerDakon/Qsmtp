/** \file qremote.c
 \brief main functions of Qremote

 This file contains the main function, the configuration and error handling of Qremote,
 the drop-in replacement for qmail-remote.
 */

#include <qremote/qremote.h>

#include <control.h>
#include <ipme.h>
#include <log.h>
#include <netio.h>
#include <qdns.h>
#include <qmaildir.h>
#include <qremote/conn.h>
#include <qremote/greeting.h>
#include <qremote/qrdata.h>
#include <qremote/starttlsr.h>
#include <sstring.h>
#include <tls.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

int socketd = -1;
unsigned int smtpext;	/**< the SMTP extensions supported by the remote server */
char *rhost;		/**< the DNS name (if present) and IP address of the remote server to be used in log messages */
size_t rhostlen;	/**< valid length of rhost */
char *partner_fqdn;	/**< the DNS name of the remote server (forward-lookup), or NULL if the connection was done by IP */

/**
 * @brief send QUIT to the remote server and close the connection
 *
 * This will properly shut down the connection to the remote server but will
 * not terminate the program.
 */
void
quitmsg(void)
{
	netwrite("QUIT\r\n");
	do {
		/* don't care about what he replies: we want to quit, if he don't want us to he must pay money *eg* */
		if (net_read(0)) {
			log_write(LOG_ERR, "network read error while waiting for QUIT reply");
			break;
		}
	} while ((linein.len >= 4) && (linein.s[3] == '-'));
	if (ssl) {
		ssl_free(ssl);
		ssl = NULL;
	}
	close(socketd);
	socketd = -1;

	free(partner_fqdn);
	partner_fqdn = NULL;
	free(rhost);
	rhost = NULL;
	free(clientcertbuf);
	clientcertbuf = NULL;
	clientcertname = "control/clientcert.pem";
}

void
net_conn_shutdown(const enum conn_shutdown_type sd_type)
{
	if ((sd_type == shutdown_clean) && (socketd >= 0)) {
		quitmsg();
	} else if (socketd >= 0) {
		close(socketd);
		socketd = -1;

		if (ssl != NULL) {
			ssl_free(ssl);
			ssl = NULL;
		}

		free(partner_fqdn);
		free(rhost);
		free(clientcertbuf);
	}

#ifdef USESYSLOG
	closelog();
#endif

	free(heloname.s);
	if (msgdata != MAP_FAILED)
		munmap((void*)msgdata, msgsize);

	exit(0);
}

void
err_mem(const int doquit)
{
	write_status("Z4.3.0 Out of memory.");

	net_conn_shutdown(doquit ? shutdown_clean : shutdown_abort);
}

void
err_conf(const char *errmsg)
{
	const char *msg[] = {errmsg, NULL};
	err_confn(msg, NULL);
}

/**
 * @brief log a configuration error and exit
 * @param errmsg array of strings to combine to the message to log
 * @param freebuf a pointer to a buffer passed to free() after logging
 *
 * Use freebuf if the contents of this buffer need to be part of errmsg.
 * If you do not have anything to free just pass NULL.
 */
void
err_confn(const char **errmsg, void *freebuf)
{
	log_writen(LOG_ERR, errmsg);
	free(freebuf);

	write_status("Z4.3.0 Configuration error.");
	net_conn_shutdown(shutdown_clean);
}

static void
setup(void)
{
#ifdef USESYSLOG
	openlog("Qremote", LOG_PID, LOG_MAIL);
#endif

	/* Block SIGPIPE, otherwise the process will get killed when the remote
	 * end cancels the connection improperly. */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGPIPE);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		write_status("Z4.3.0 Cannot block SIGPIPE.");

		net_conn_shutdown(shutdown_abort);
	}

	remote_common_setup();

#ifdef CHUNKING
	unsigned long chunk;
	if (loadintfd(openat(controldir_fd, "chunksizeremote", O_RDONLY | O_CLOEXEC), &chunk, 32768) < 0) {
		err_conf("parse error in control/chunksizeremote");
	} else {
		if (chunk >= ((unsigned long)1 << 31)) {
			err_conf("chunksize in control/chunksizeremote too big");
		}
		chunksize = chunk & 0xffffffff;
	}
#endif

#ifdef DEBUG_IO
	do_debug_io = (faccessat(controldir_fd, "Qremote_debug", R_OK, 0) == 0);
#endif
}

int
main(int argc, char *argv[])
{
	struct ips *mx = NULL;
	int rcptcount = argc - 3;
	struct stat st;

	/* do this check before opening any files to catch the case that fd 0 is closed at this point */
	int i = fstat(0, &st);

	setup();

	if (rcptcount <= 0) {
		log_write(LOG_CRIT, "too few arguments");
		write_status("Z4.3.0 internal error: Qremote called with invalid arguments");
		net_conn_shutdown(shutdown_abort);
	}

	/* this shouldn't fail normally: qmail-rspawn did it before successfully */
	if (i != 0) {
		if (errno == ENOMEM)
			err_mem(0);
		log_write(LOG_CRIT, "can't fstat() input");
		write_status("Z4.3.0 internal error: can't fstat() input");
		net_conn_shutdown(shutdown_abort);
	}
	msgsize = st.st_size;
	msgdata = mmap(NULL, msgsize, PROT_READ, MAP_SHARED, 0, 0);

	if (msgdata == MAP_FAILED) {
		log_write(LOG_CRIT, "can't mmap() input");
		write_status("Z4.3.0 internal error: can't mmap() input");
		net_conn_shutdown(shutdown_abort);
	}

	getmxlist(argv[1], &mx);
	if (targetport == 25) {
		mx = filter_my_ips(mx);
		if (mx == NULL) {
			const char *msg[] = { "Z4.4.3 all mail exchangers for ",
					argv[1], " point back to me" };
			write_status_m(msg, 3);
			net_conn_shutdown(shutdown_abort);
		}
	}
	sortmx(&mx);

	i = connect_mx(mx, &outgoingip, &outgoingip6);
	freeips(mx);

	if (i < 0) {
		write_status("Z4.4.2 can't connect to any server");
		net_conn_shutdown(shutdown_abort);
	}

	if (ssl) {
		successmsg[3] = "message ";
		successmsg[4] = SSL_get_cipher(ssl);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
		if (SSL_get0_dane_tlsa(ssl, NULL, NULL, NULL, NULL, NULL) > 0)
			successmsg[5] = " encrypted and DANE secured";
		else
#endif
			successmsg[5] = " encrypted";
	}

/* check if message is plain ASCII or not */
	const unsigned int recodeflag = need_recode(msgdata, msgsize);

	if (send_envelope(recodeflag, argv[2], argc - 3, argv + 3) != 0)
		net_conn_shutdown(shutdown_clean);

	successmsg[0] = rhost;
#ifdef CHUNKING
	if (smtpext & esmtp_chunking) {
		send_bdat(recodeflag);
	} else {
#else
	{
#endif
		send_data(recodeflag);
	}
	net_conn_shutdown(shutdown_clean);
}
