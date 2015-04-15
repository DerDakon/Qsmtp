#include <qsmtpd/commands.h>

#include <fmt.h>
#include <netio.h>
#include <qdns.h>
#include <qsmtpd/antispam.h>
#include <qsmtpd/queue.h>
#include <qsmtpd/qsauth.h>
#include <qsmtpd/qsmtpd.h>
#include <qsmtpd/syntax.h>
#include <qsmtpd/userconf.h>
#include <qsmtpd/userfilters.h>
#include <qsmtpd/xtext.h>
#include <sstring.h>
#include "test_io/testcase_io.h"

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>

struct xmitstat xmitstat;
int relayclient;
char *rcpthosts;
off_t rcpthsize;
unsigned int rcptcount;
int submission_mode;
static unsigned int expected_bugoffset;
static int expected_tls_verify;
static int tls_verify_result;
struct recip *thisrecip;
unsigned int goodrcpt;
int badbounce;
int controldir_fd = AT_FDCWD;
unsigned long databytes = 20000;

static int errcnt;

rcpt_cb rcpt_cbs[] = {
	NULL
};

const char *blocktype[] = { (const char *)(uintptr_t)(-1) };

/* make sure they will never be accessed */
string heloname = {
	.s = (char *)((uintptr_t)-1),
	.len = -1
};
string liphost = {
	.s = (char *)((uintptr_t)-1),
	.len = -1
};
unsigned long comstate = 0x10000000;
struct smtpcomm *current_command = (struct smtpcomm *)((uintptr_t)-1);

void
userconf_init(struct userconf *ds)
{
	memset(ds, 0, sizeof(*ds));
	ds->domaindirfd = -3;
	ds->userdirfd = -5;
}

void
userconf_free(struct userconf *ds)
{
	assert(ds->domaindirfd == -3);
	assert(ds->userdirfd == -5);
}

/* used by other commands, but not by smtp_from() */
void
freedata(void)
{
	abort();
}

void
conn_cleanup(const int rc __attribute__ ((unused)))
{
	abort();
}

char *
smtp_authstring(void)
{
	abort();
}

int
check_host(const char *a)
{
	if (a == NULL) {
		return SPF_NONE;
	} else if (strcmp(a, "spferror.example.net") == 0) {
		errno = EPIPE; /* easily detectable */
		return -1;
	} else if (strcmp(a, "spf.example.net") == 0) {
		return SPF_PASS;
	} else {
		return SPF_NONE;
	}
}

void
sync_pipelining(void)
{
	abort();
}

void
queue_reset(void)
{
	abort();
}

/* may in theory be used, but since the files opened before are
 * not there the flow should never reach this. */
int
lookupipbl(int x __attribute__ ((unused)))
{
	abort();
}

int
finddomain(const char *buf, const off_t size, const char *domain)
{
	assert(buf == rcpthosts);
	assert(size == rcpthsize);

	/* assume only example.org is local */
	return (strcmp(domain, "@example.org") == 0);
}

int
user_exists(const string *localpart, const char *domain, struct userconf *ds)
{
	assert(strcmp(domain, "example.org") == 0);
	assert(ds == NULL);

	if (localpart->len != 3)
		return 0;

	if ((strncmp(localpart->s, "foo", 3) == 0) || (strncmp(localpart->s, "bar", 3) == 0))
		return 1;

	return 0;
}

long
getsetting(const struct userconf *ds, const char *key, enum config_domain *t)
{
	const char *conf;
	if (ds->userconf != NULL) {
		*t = CONFIG_USER;
		conf = *ds->userconf;
	} else if (ds->domainconf != NULL) {
		*t = CONFIG_DOMAIN;
		conf = *ds->domainconf;
	} else {
		*t = CONFIG_NONE;
		return 0;
	}

	assert(strlen(conf) > 2);

	if (strcmp(key, "fail_hard_on_temp") == 0)
		return (conf[1] == 'f');
	else if (strcmp(key, "nonexist_on_block") == 0)
		return (conf[2] == 'n');
	else
		abort();
}

static const char *err_m1, *err_m2;

int
err_control2(const char *m1, const char *m2)
{
	assert((err_m1 == NULL) == (err_m2 == NULL));

	if (err_m1 == NULL)
		abort();

	if (strcmp(err_m1, m1) != 0) {
		fprintf(stderr, "%s('%s', '%s') was called, but '%s' was expected as first argument\n",
				__func__, m1, m2, err_m1);
		abort();
	}

	if (strcmp(err_m2, m2) != 0) {
		fprintf(stderr, "%s('%s', '%s') was called, but '%s' was expected as second argument\n",
			__func__, m1, m2, err_m2);
		abort();
	}

	return 0;
}

int
tls_verify(void)
{
	assert(expected_tls_verify);

	expected_tls_verify = 0;

	return tls_verify_result;
}

void
tarpit(void)
{
	abort();
}

int
userconf_load_configs(struct userconf *ds __attribute__ ((unused)))
{
	abort();
}

int
test_ask_dnsmx(const char *name, struct ips **res)
{
	if (strcmp(name, "strange.example.org") == 0) {
		errno = ENOTBLK; /* easily detectable */
		return DNS_ERROR_LOCAL;
	} else if (strcmp(name, "example.org") == 0) {
		*res = malloc(sizeof(**res));
		if (*res == NULL)
			exit(ENOMEM);

		memset(*res, 0, sizeof(**res));
		(*res)->addr = malloc(sizeof(*(*res)->addr));
		if ((*res)->addr == NULL) {
			free(*res);
			exit(ENOMEM);
		}

		(*res)->name = strdup("mx.example.net");
		if ((*res)->name == NULL) {
			free((*res)->addr);
			free(*res);
			exit(ENOMEM);
		}

		(*res)->count = 1;
		inet_pton(AF_INET6, "", (*res)->addr);

		return 0;
	}

	return 1;
}

int
main(void)
{
	struct {
		struct xmitstat xmitstat;
		const char *input;
		unsigned int bugoffset;
		unsigned int tls_verify:1;	/* call to tls_verify() is permitted */
		int tls_verify_result;
		int from_result;	/* expected result of smtp_from() */
		const char *netmsg;
	} testdata[] = {
		/* simple acceptance */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "foo@example.org"
				},
			},
			.input = "MAIL FROM:<foo@example.org>",
			.netmsg = "250 2.1.5 sender <foo@example.org> is syntactically correct\r\n",
		},
		/* again, but SIZE given */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "foo@example.org"
				},
				.esmtp = 1,
				.thisbytes = 12345
			},
			.input = "MAIL FROM:<foo@example.org> SIZE=12345",
			.netmsg = "250 2.1.5 sender <foo@example.org> is syntactically correct\r\n",
		},
		/* again, but too large SIZE given */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.input = "MAIL FROM:<foo@example.org> SIZE=123450",
			.netmsg = "452 4.3.1 Requested action not taken: insufficient system storage\r\n",
			.from_result = EDONE
		},
		/* SIZE given, but not in ESMTP mode */
		{
			.input = "MAIL FROM:<foo@example.org> SIZE=12345",
			.from_result = EINVAL
		},
		/* SIZE given, but not in ESMTP mode */
		{
			.input = "MAIL FROM:<foo@example.org> SIZE=12345",
			.from_result = EINVAL
		},
		/* valid size, valid body, valid empty auth */
		{
			.xmitstat = {
				.datatype = 1,
				.esmtp = 1,
				.thisbytes = 20
			},
			.input = "mail from:<> size=20 body=8bitmime auth=<>",
			.netmsg = "250 2.1.5 sender <> is syntactically correct\r\n"
		},
		/* duplicate size */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.input = "mail from:<> size=20 size=20",
			.from_result = EINVAL
		},
		/* duplicate body */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.input = "mail from:<> body=7bit body=7bit",
			.from_result = EINVAL
		},
		/* invalid size */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.input = "mail from:<> size=a",
			.from_result = EINVAL
		},
		/* invalid size, space bug */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.bugoffset = 1,
			.input = "mail from: <> size=2a",
			.from_result = EINVAL
		},
		/* invalid body arguments */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.input = "mail from:<> body=foo",
			.from_result = EINVAL
		},
		/* invalid auth argument */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.input = "mail from:<> auth=",
			.from_result = EINVAL
		},
		/* size given more than once */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.input = "mail from:<> size=0 size=2",
			.from_result = EINVAL
		},
		/* auth given more than once */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.input = "mail from:<> auth=<> auth=<>",
			.from_result = EINVAL
		},
		/* no space between > and size */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.input = "mail from:<>size=20",
			.from_result = EINVAL
		},
		/* no space between 7BIT and size */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.input = "mail from:<> body=7BITsize=20",
			.from_result = EINVAL
		},
		/* bad extension name */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.input = "mail from:<> foo=bar",
			.from_result = EBADRQC
		},
		/* bad extension name, followed by something valid */
		{
			.xmitstat = {
				.esmtp = 1
			},
			.input = "mail from:<> foo=bar size=20",
			.from_result = EBADRQC
		},
		{
			.input = NULL
		}
	};
	unsigned int i;

	testcase_setup_net_writen(testcase_net_writen_combine);
	testcase_setup_netnwrite(testcase_netnwrite_compare);
	testcase_setup_ask_dnsmx(test_ask_dnsmx);
	/* FIXME: replace this by a checker */
	testcase_setup_log_writen(testcase_log_writen_console);

	for (i = 0; testdata[i].input != NULL; i++) {
		int r;
		char ulbuf[ULSTRLEN];

		linein.len = strlen(testdata[i].input);
		assert(linein.len < TESTIO_MAX_LINELEN);

		/* initialize environment */
		strcpy(linein.s, testdata[i].input);
		xmitstat = testdata[i].xmitstat;
		expected_bugoffset = testdata[i].bugoffset;
		expected_tls_verify = testdata[i].tls_verify;
		tls_verify_result = testdata[i].tls_verify_result;
		netnwrite_msg = testdata[i].netmsg;

		STREMPTY(xmitstat.mailfrom);
		xmitstat.datatype = 0;
		xmitstat.thisbytes = 0;

		r = smtp_from();

		if (r != testdata[i].from_result) {
			fprintf(stderr, "%u: smtp_from() returned %i instead of %i\n",
					i, r, testdata[i].from_result);
			errcnt++;
		}

		if (testdata[i].xmitstat.mailfrom.s == NULL) {
			if ((xmitstat.mailfrom.s != NULL) || (xmitstat.mailfrom.len != 0)) {
				fprintf(stderr, "%u: smtp_from() set xmitstat.mailfrom to '%s'/%zu, but NULL/0 was expected\n",
						i, xmitstat.mailfrom.s, xmitstat.mailfrom.len);
				errcnt++;
			}
		} else {
			assert(testdata[i].from_result == 0);
			if (xmitstat.mailfrom.s == NULL) {
				fprintf(stderr, "%u: smtp_from() set xmitstat.mailfrom to NULL/%zu, but '%s'/%zu was expected\n",
						i, xmitstat.mailfrom.len, testdata[i].xmitstat.mailfrom.s, strlen(testdata[i].xmitstat.mailfrom.s));
				errcnt++;
			} else if ((xmitstat.mailfrom.len != strlen(testdata[i].xmitstat.mailfrom.s)) || (strcmp(xmitstat.mailfrom.s, testdata[i].xmitstat.mailfrom.s) != 0)) {
				fprintf(stderr, "%u: smtp_from() set xmitstat.mailfrom to %s/%zu, but '%s'/%zu was expected\n",
						i, xmitstat.mailfrom.s, xmitstat.mailfrom.len, testdata[i].xmitstat.mailfrom.s, strlen(testdata[i].xmitstat.mailfrom.s));
				errcnt++;
			}
			free(xmitstat.mailfrom.s);
		}

		if (r == 0) {
			// TODO: check frommx
			freeips(xmitstat.frommx);
		} else {
			if (xmitstat.frommx != NULL) {
				fprintf(stderr, "%u: smtp_from() returned %i, but set frommx\n",
						i, r);
				freeips(xmitstat.frommx);
				errcnt++;
			}
		}

		if (xmitstat.thisbytes != testdata[i].xmitstat.thisbytes) {
			fprintf(stderr, "%u: smtp_from() set thisbytes to %zu, but %zu was expected\n",
					i, xmitstat.thisbytes, testdata[i].xmitstat.thisbytes);
			errcnt++;
		}

		if (xmitstat.datatype != testdata[i].xmitstat.datatype) {
			fprintf(stderr, "%u: smtp_from() set datatype to %u, but %u was expected\n",
					i, xmitstat.datatype, testdata[i].xmitstat.datatype);
			errcnt++;
		}

		if (xmitstat.spacebug != !!testdata[i].bugoffset) {
			fprintf(stderr, "%u: smtp_from() set spacebug to %u, but %u was expected\n",
					i, xmitstat.spacebug, !!testdata[i].bugoffset);
			errcnt++;
		}

		snprintf(ulbuf, sizeof(ulbuf), "%u", i);
		errcnt += testcase_netnwrite_check(ulbuf);
	}

	return errcnt;
}
