#include <stdlib.h>
#include <string.h>
#include "usercallback.h"
#include "netio.h"
#include "qsmtpd.h"

/**
 * This checks if the combination of "MAIL FROM:" and "HELO" look like SoberG
 *
 * SoberG's MAIL FROM: foo@bar.com would lead to HELO foo.com
 */
int
cb_soberg(const struct userconf *ds, char **logmsg, int *t)
{
	int rc = 0;		/* return code */
	char *soberhelo;	/* the helo expected it it is a SoberG */
	char *at;		/* '@' in the mailfrom */
	char *tld;		/* begin of the top level domain in mailfrom */
	unsigned int userl, tldl; /* */

	if (!xmitstat.mailfrom.len)
		return 0;
	/* This rule is very tricky, normally you want bounce messages.
	 * But if you are sure that there can't be any bounce messages (e.g. the address
	 * is only used on a website or as a usenet From or Reply-To address) this will
	 * block bounces from spamruns, joe-jobs and braindead virus scanners */
	if (!getsettingglobal(ds, "block_soberg", t))
		return 0;

	/* this can't fail, either mailfrom.len is 0 or there is an '@' and at least one '.',
	 * addrsyntax() checks this before */
	at = strchr(xmitstat.mailfrom.s, '@');
	tld = strrchr(xmitstat.mailfrom.s, '.');

	userl = at - xmitstat.mailfrom.s;
	tldl = strlen(tld);
	soberhelo = malloc(userl + tldl);
	if (!soberhelo) {
		errno = ENOMEM;
		return -1;
	}
	memcpy(soberhelo, xmitstat.mailfrom.s, userl - 1);
	/* copy one byte more than strlen(tld): this copies also the '\0' */
	memcpy(soberhelo + userl, tld, tldl + 1);
	rc = strcmp(xmitstat.helostr.s, soberhelo);
	free(soberhelo);
	if (rc)
		return 0;

	rc = netwrite("550 5.7.1 mail looks like SoberG worm\r\n");
	*logmsg = "SoberG suspect";
	return rc ? rc : 1;
}
