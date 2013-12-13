/** \file addrparse.c
 \brief validate email addresses
 */
#include <qsmtpd/addrparse.h>

#include <qsmtpd/antispam.h>
#include <control.h>
#include <netio.h>
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/userconf.h>
#include <qsmtpd/vpop.h>

/**
 * @brief check an email address for syntax errors and/or existence
 *
 * @param in input to parse
 * @param flags \arg \c 1: rcpt to checks (e.g. source route is allowed) \arg \c 0: mail from checks
 * @param addr struct string to contain the address (memory will be malloced, is set if 0 or -1 is returned)
 * @param more here starts the data behind the first '>' behind the first '<' (or NULL if none)
 * @param ds store the userconf of the user here
 * @return if address was validated
 * @retval 0 address exists locally
 * @retval >0 on error (e.g. ENOMEM, return code is error code)
 * @retval -2 if address not local (this is of course no error condition for MAIL FROM)
 * @retval -1 if address local but nonexistent (expired or most probably faked) _OR_ if
 *          domain of address does not exist (in both cases error is sent to network
 *          before leaving)
 */
int
addrparse(char *in, const int flags, string *addr, char **more, struct userconf *ds, const char *rcpthosts, const off_t rcpthsize)
{
	char *at;			/* guess! ;) */
	int result = 0;			/* return code */
	int i, j;
	string localpart;
	const char *lookupdomain;	/*  the domain to lookup in user backend */

	j = addrsyntax(in, flags, addr, more);
	if ((j == 0) || ((flags != 1) && (j == 4))) {
		tarpit();
		return netwrite("501 5.1.3 domain of mail address is syntactically incorrect\r\n") ? errno : EBOGUS;
	} else if (j < 0) {
		return errno;
	}

	/* empty mail address is valid in MAIL FROM:, this is checked by addrsyntax before
	 * if we find an empty address here it's ok */
	if (!addr->len)
		return 0;
	at = strchr(addr->s, '@');
	/* check if mail goes to global postmaster */
	if (flags && !at)
		return 0;
	if (j < 4) {
		/* at this point either @ is set or addrsyntax has already caught this */
		i = finddomainmm(rcpthosts, rcpthsize, at + 1);

		if (!i)
			return -2;

		lookupdomain = at + 1;
	} else {
		const size_t liplen = strlen(xmitstat.localip);
		size_t intro = strlen("@[");

		j = 0;
		if (strncmp(at + intro, "IPv6:", strlen("IPv6:")) == 0)
			intro += strlen("IPv6:");

		/* FIXME: this fails if the representations of the IPv6 address don't match */
		if ((strncmp(at + intro, xmitstat.localip, liplen) != 0) ||
					(*(at + intro + liplen) != ']'))
			goto nouser;

		lookupdomain = liphost.s;
	}

/* get the domain directory from "users/cdb" */
	result = vget_dir(lookupdomain, &(ds->domainpath));
	if (result < 0) {
		if (result == -ENOENT)
			return 0;
		result = -result;
		goto free_and_out;
	} else if (!result) {
		/* the domain is not local (or at least no vpopmail domain) so we can't say it the user exists or not:
		 * -> accept the mail */
		return 0;
	}

/* get the localpart out of the RCPT TO */
	localpart.len = (at - addr->s);
	localpart.s = addr->s;

	j = user_exists(&localpart, ds);
	if (j < 0) {
		result = errno;
		goto free_and_out;
	}

nouser:
	if (!j) {
		const char *logmsg[] = {"550 5.1.1 no such user <", addr->s, ">", NULL};

		userconf_free(ds);
		tarpit();
		result = net_writen(logmsg) ? errno : -1;
		if (result > 0) {
			free(addr->s);
			STREMPTY(*addr);
		}
		return result;
	}
	return 0;
free_and_out:
	userconf_free(ds);
	free(addr->s);
	STREMPTY(*addr);
	return result;
}
