#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include "userfilters.h"
#include "qsmtpd.h"
#include "netio.h"
#include "log.h"

#define WRITE(fd, msg, size) if (write(fd, msg, size) < 0) goto err_write;
#define WRITEl(fd, msg) WRITE(fd, msg, strlen(msg))

int
cb_postfix(const struct userconf *ds, char **logmsg, int *t)
{
	int rc;
	char buf[ULSTRLEN];
	char actionbuf[1024];
	ssize_t res;
	struct pfixpol *pf = pfixhead.tqh_first;

#warning FIXME: let user configure which daemons to use

	while (pf) {
		if (!pf->pid) {
			struct sockaddr_un sa;
			/* daemon is not running. Fork one */

			pf->fd = socket(PF_LOCAL, SOCK_STREAM, 0);
			if (!pf->fd) {
				*logmsg = "cannot create socket to policy daemon";
				return 4;
			}
			memcpy(sa.sun_path, PFIXSPOOLDIR, strlen(PFIXSPOOLDIR));
			memcpy(sa.sun_path + 17, pf->name, strlen(pf->name));
			sa.sun_path[17 + strlen(pf->name)] = '\0';
			if (bind(pf->fd, (const struct sockaddr *) &sa, sizeof(sa))) {
				*logmsg = "cannot bind to socket to policy daemon";
				close(pf->fd);

				return 4;
			}

			switch ( (pf->pid = fork()) ) {
				case -1:	*logmsg = "cannot fork policy daemon";
						return 4;
				case 0:		{
#warning FIXME: close orgy missing here
						char sockf[strlen(sa.sun_path) + 6];
						char *args[] = {pf->name, sockf, NULL};
						char cmdname[strlen(PFIXPOLDIR) + 2 + strlen(pf->name)];

						memcpy(cmdname, PFIXPOLDIR "/", strlen(PFIXPOLDIR) + 1);
						memcpy(cmdname + strlen(PFIXPOLDIR) + 1, pf->name, strlen(pf->name));
						cmdname[strlen(PFIXPOLDIR) + 1 + strlen(pf->name)] = '\0';

						memcpy(sockf, "unix:", 5);
						memcpy(sockf + 5, sa.sun_path, strlen(sa.sun_path));
						sockf[sizeof(sockf) - 1] = '\0';

						munmap(rcpthosts, rcpthsize);

						execv(cmdname, args);
						return 1;
						}
			}
			if (connect(pf->fd, (const struct sockaddr *) &sa, sizeof(sa))) {
				*logmsg = "cannot connect to socket to policy daemon";
				close(pf->fd);
				kill(pf->pid, SIGTERM);
				sleep(3);
				if (waitpid(pf->pid, &rc, WNOHANG))
					kill(pf->pid, SIGKILL);
				pf->pid = 0;

				return 4;
			}
		}
	
		*logmsg = "policy daemon";
		WRITEl(pf->fd, "request=smtpd_access_policy\n");
		WRITEl(pf->fd, "protocol_state=RCPT\n");
		WRITEl(pf->fd, "protocol_name=");
		if (xmitstat.esmtp)
			WRITE(pf->fd, "E", 1);
		WRITE(pf->fd, "SMTP\n", 5);
		WRITEl(pf->fd, "helo_name=");
		WRITE(pf->fd, HELOSTR, HELOLEN);
		WRITEl(pf->fd, "\nsender=");
		if (xmitstat.mailfrom.len)
			WRITE(pf->fd, xmitstat.mailfrom.s, xmitstat.mailfrom.len);
		WRITEl(pf->fd, "\nrecipient=");
		WRITE(pf->fd, THISRCPT, thisrecip->to.len);
		WRITE(pf->fd, "\nclient_address=", 1);
		WRITEl(pf->fd, xmitstat.ipv4conn ? xmitstat.remoteip + 7 : xmitstat.remoteip);
		if (xmitstat.thisbytes) {
			WRITEl(pf->fd, "\nsize=");
			ultostr(xmitstat.thisbytes, buf);
			WRITEl(pf->fd, buf);
		}
		WRITEl(pf->fd, "\nsasl_username=");
		WRITE(pf->fd, xmitstat.authname.s, xmitstat.authname.len);
		WRITEl(pf->fd, "\nclient_name=");
		WRITE(pf->fd, xmitstat.remotehost.s, xmitstat.remotehost.len);
		WRITE(pf->fd, "\n\n", 2);
		res = read(pf->fd, actionbuf, sizeof(actionbuf) - 1);
		actionbuf[res] = '\0';
		if (res < 0)
			return res;
		if (!strcasecmp(actionbuf, "action=")) {
			const char *emsg[] = {"unsupported response from policy daemon: ", actionbuf, NULL};
			char *s = strchr(actionbuf, '\n');
	
			if (s)
				*s = '\0';
	
			log_writen(LOG_WARNING, emsg);
		} else if (!strcasecmp(actionbuf + 6, "dunno\n\n")) {
			/* fall through */
		} else if (!strcasecmp(actionbuf + 6, "ok\n\n")) {
			return 5;
		} else if (!strncasecmp(actionbuf + 6, "defer_if_permit", 15)) {
			return 4;
		} else if (!strncasecmp(actionbuf + 6, "reject", 6) && ((actionbuf[12] == ' ') || (actionbuf[12] == '\n'))) {
			if (actionbuf[12] == '\n') {
				return 2;
			} else {
				return 1;
			}
		} else {
			const char *emsg[] = {"unsupported action: ", actionbuf + 6, NULL};
			char *s = strchr(actionbuf + 6, '\n');
	
			if (s)
				*s = '\0';
	
			log_writen(LOG_WARNING, emsg);
		}
		pf = pf->entries.tqe_next;
	}
	return 0;
err_write:
	kill(pf->pid, SIGTERM);
	*logmsg = "error writing to postfix policy daemon";
	sleep(3);
	if (waitpid(pf->pid, &rc, WNOHANG))
		kill(pf->pid, SIGKILL);
	pf->pid = 0;
	return 4;
}
