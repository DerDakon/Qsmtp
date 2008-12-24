#include <sys/mman.h>
#include <sys/stat.h>
#include <ctype.h>
#include <syslog.h>
#include <unistd.h>
#include "log.h"
#include "netio.h"
#include "qsmtpd.h"
#include "userfilters.h"

/**
 * The user does not want to receive any mail
 *
 * There are three possibilities how to work with the config file "nomail"
 * -if it is empty the mail will simply be rejected with a general error
 *  message
 * -if the message starts with "XYY X.Y.Y" (where Y is a decimal number
 *  and X is either 4 or 5) this will be used as the error code.
 * -if the message does not start with a SMTP rejection code it will be used
 *  with a rejection code of "550 5.7.1 ".
 */
int
cb_nomail(const struct userconf *ds, char **logmsg, int *t)
{
	int rc = 0;		/* return code */
	struct stat st;
	char *rejmsg;
	int fd;
	int i;
	int codebeg;		/* message begins with reject code */

	if ( (fd = getfile(ds, "nomail", t)) < 0)
		return (errno != ENOENT) ? fd : 0;

	rc = fstat(fd, &st);
	if (rc == -1) {
		int e = errno;
		do {
			i = close(fd);
		} while ((i == -1) && (errno == EINTR));
		errno = e;
		return rc;
	}

	*logmsg = "nomail";

	if (st.st_size == 0) {
		do {
			rc = close(fd);
		} while ((rc == -1) && (errno == EINTR));
		return rc ? rc : 2;
	}

	rejmsg = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (rejmsg == MAP_FAILED) {
		int e = errno;
		do {
			i = close(fd);
		} while ((i == -1) && (errno == EINTR));
		errno = e;
		return -1;
	}

	codebeg = 0;
	if (st.st_size > 10) {
		codebeg = 1;
		for (i = 0; (i < 10) && codebeg; i++) {
			switch (i) {
			case 0:
				codebeg = ((rejmsg[0] == '4') ||
						(rejmsg[0] == '5'));
				break;
			case 3:
			case 9:
				codebeg = (rejmsg[i] == ' ');
				break;
			case 4: codebeg = (rejmsg[4] == rejmsg[0]);
				break;
			case 5:
			case 7:
				codebeg = (rejmsg[i] == '.');
				break;
			default:
				codebeg = isdigit(rejmsg[i]);
				break;
			}
		}
	}

	if (codebeg) {
		const char *netmsg[] = { rejmsg, NULL };
		rc = net_writen(netmsg);
	} else {
		const char *netmsg[] = { "550 5.7.1 ", rejmsg, NULL };
		rc = net_writen(netmsg);
	}

	munmap(rejmsg, st.st_size);
	do {
		i = close(fd);
	} while ((i == -1) && (errno == EINTR));

	return rc ? rc : 1;
}
