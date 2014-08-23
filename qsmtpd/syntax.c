/** \file syntax.c
 \brief syntax checking helper functions

 This file contains functions to needed to handle syntax errors in input
 commands.
 */

#include <qsmtpd/syntax.h>

#include <log.h>
#include <netio.h>
#include <qsmtpd/commands.h>
#include <qsmtpd/qsmtpd.h>

#include <string.h>
#include <syslog.h>

#define MAXBADCMDS	5		/**< maximum number of illegal commands in a row */

int badcmds;

/**
 * \brief check if the amount of bad commands was reached
 *
 * If the client has sent too many consecutive bad commands the
 * connection will be terminated.
 */
void
check_max_bad_commands(void)
{
	const char *msg[] = {"dropped connection from [", xmitstat.remoteip,
	"] {too many bad commands}", NULL };

	if (badcmds++ <= MAXBADCMDS)
		return;

	/* -ignore possible errors here, we exit anyway
	 * -don't use tarpit: this might be a virus or something going wild,
	 *  tarpit would allow him to waste even more bandwidth */
	netwrite("550-5.7.1 too many bad commands\r\n");
	log_writen(LOG_INFO, msg);
	netwrite("550 5.7.1 die slow and painful\r\n");

	conn_cleanup(0);
}

/**
 * \brief run the SMTP command loop but only accept QUIT
 *
 * This will reject all commands but quit with "bad sequence of commands",
 * possibly closing the connection if seeing too many of them.
 */
void
wait_for_quit(void)
{
	const char quitcmd[] = "QUIT";

	/* this is the bastard version of the main command loop */
	while (1) {
		/* once again we don't care for the return code here as we only want to get rid of this session */
		(void) net_read();

		if (!strncasecmp(linein.s, quitcmd, strlen(quitcmd))) {
			if (!linein.s[strlen(quitcmd)])
				smtp_quit();
		}
		check_max_bad_commands();
		(void) netwrite("503 5.5.1 Bad sequence of commands\r\n");
	}
}

/**
 * \brief check if there are already commands in the pipeline
 *
 * This function should be called directly after the last command in a
 * pipelined command group, before the command sends out it's response.
 * If there is something in the command pipeline all following commands
 * will be handled as errors until the client disconnects.
 *
 * This function will only return if everything is fine.
 *
 * This may be called regardless if the session is using ESMTP or not.
 */
void
sync_pipelining(void)
{
	int i = data_pending();
	if (i == 0)
		return;
	if (i < 0)
		dieerror(-i);

	/* if we are not using ESMTP PIPELINING isn't allowed. Use a different
	 * error code. */
	if (!xmitstat.esmtp)
		hasinput(1);

	/* Ok, that was simple, we have a pipelining error here.
	 * First announce that something went wrong. */
	(void) netwrite("503 5.5.1 SMTP command sent after end of PIPELINING command group\r\n");

	wait_for_quit();
}

/**
 * \brief check if there is already more input from network available
 * \param quitloop if set the command will loop until the client disconnects if there is input data
 * \returns error code if data is available or error happens
 * \retval 0 if no input
 * \retval EBOGUS if quitloop is 0 and there is input
 *
 * This function should only be used in situations where the client should NOT
 * have sent any more data, i.e. where he must wait for our reply before sending
 * more. This is a sign of a broken SMTP engine on the other side, the input should
 * not be used anymore.
 *
 * This function will return an error code regardless of the setting of quitloop when
 * something on our side goes wrong.
 */
int
hasinput(const int quitloop)
{
	int rc = data_pending();

	if (rc <= 0)
		return -rc;

	/* there is input data pending. This means the client sent some before our
	 * reply. His SMTP engine is broken so we don't let him send the mail */
	/* first: consume the first line of input so client will trigger the bad
	 * commands counter if he ignores everything we send */
	rc = net_read() ? errno : 0;
	if (rc)
		return rc;

	if (netwrite("550 5.5.0 you must wait for my reply\r\n"))
		return errno;

	if (quitloop)
		wait_for_quit();
	else
		return EBOGUS;
}
