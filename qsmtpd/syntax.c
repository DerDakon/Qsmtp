/** \file syntax.c
 \brief syntax checking helper functions

 This file contains functions to needed to handle syntax errors in input
 commands.
 */
#include "syntax.h"

#include "log.h"
#include "netio.h"
#include "qsmtpd.h"

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
 * \brief so the SMTP command loop but only accept QUIT
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

		if (!strncasecmp(linein, quitcmd, strlen(quitcmd))) {
			if (!linein[strlen(quitcmd)])
				smtp_quit();
		}
		check_max_bad_commands();
		(void) netwrite("503 5.5.1 Bad sequence of commands\r\n");
	}
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
	int rc;

	if ( (rc = data_pending()) < 0)
		return errno;
	if (!rc)
		return 0;

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
