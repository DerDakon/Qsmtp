#include <qsmtpd/commands.h>

#include <netio.h>
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

struct xmitstat xmitstat;
int relayclient;
char *rcpthosts;
off_t rcpthsize;
unsigned int rcptcount;
int submission_mode;
static unsigned int expected_bugoffset;
static int expected_tls_verify;
static int tls_verify_result;
static int expected_tarpit;
struct recip *thisrecip;
unsigned int goodrcpt;
int badbounce;
int controldir_fd = AT_FDCWD;

static int expected_uc_load = -1;

static int errcnt;

static enum filter_result
cb_first(const struct userconf *ds __attribute__ ((unused)), const char **logmsg, enum config_domain *t)
{
	*logmsg = "first filter";
	*t = CONFIG_USER;

	switch (xmitstat.spf) {
	case 0:
		return FILTER_PASSED;
	case 4:
		return FILTER_DENIED_TEMPORARY;
	default:
		return FILTER_DENIED_UNSPECIFIC;
	}
}

static enum filter_result
cb_second(const struct userconf *ds __attribute__ ((unused)), const char **logmsg, enum config_domain *t)
{
	*logmsg = "second filter";
	*t = CONFIG_DOMAIN;

	switch (xmitstat.helostatus) {
	case 0:
		return FILTER_PASSED;
	case 1:
		netwrite("first filter matched\r\n");
		return FILTER_DENIED_WITH_MESSAGE;
	case 2:
		return FILTER_DENIED_UNSPECIFIC;
	case 3:
		return FILTER_DENIED_NOUSER;
	case 4:
		return FILTER_DENIED_TEMPORARY;
	case 5:
		return FILTER_WHITELISTED;
	default:
		errno = 1024;
		return FILTER_ERROR;
	}
}

static enum filter_result
cb_third(const struct userconf *ds __attribute__ ((unused)), const char **logmsg, enum config_domain *t)
{
	*logmsg = "third filter";
	*t = CONFIG_GLOBAL;

	if (xmitstat.check2822 != 0)
		return FILTER_DENIED_TEMPORARY;

	return FILTER_PASSED;
}

rcpt_cb rcpt_cbs[] = {
	cb_first,
	cb_second,
	cb_third,
	NULL
};

const char *blocktype[] = { (char *)((uintptr_t)-1), "user", "domain", (char *)((uintptr_t)-1), "global", (char *)((uintptr_t)-1), (char *)((uintptr_t)-1) };

/* make sure they will never be accessed */
/* too small for anything, but noone should check */
unsigned long databytes = 1;
char *protocol = (char *)((uintptr_t)-1);
string heloname = {
	.s = (char *)((uintptr_t)-1),
	.len = -1
};
unsigned int comstate = 0x10000000;
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

/* used by other commands, but not by smtp_rcpt() */
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

int
domainvalid(const char * const a __attribute__ ((unused)))
{
	abort();
}

char *
smtp_authstring(void)
{
	abort();
}

int
check_host(const char *a __attribute__ ((unused)))
{
	abort();
}

ssize_t
xtextlen(const char *a __attribute__ ((unused)))
{
	abort();
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

/* checker functions */
int
addrparse(char *in, const int flags, string *addr, char **more, struct userconf *ds __attribute__ ((unused)), const char *rh, const off_t rs)
{
	char *br;
	int i;

	assert(rh == rcpthosts);
	assert(rs == rcpthsize);
	assert(flags == 1);

	assert(in == linein.s + 9 + expected_bugoffset);

	*more = NULL;

	br = strchr(in, '>');
	assert(br != NULL);

	i = newstr(addr, br - in + 1);
	assert(i == 0);
	strncpy(addr->s, in, addr->len - 1);
	addr->s[addr->len - 1] = '\0';

	/* nothere is not here */
	if (strcmp(addr->s, "nothere@example.org") == 0)
		return -1;

	/* assume only example.org is local */
	if (strstr(addr->s, "@example.org") == NULL)
		return -2;

	/* allow easy customization of return value in getsetting() */
	if (addr->s[0] == 'd')
		ds->domainconf = &addr->s;
	else
		ds->userconf = &addr->s;

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
	assert(expected_tarpit);

	expected_tarpit = 0;
}

int
userconf_load_configs(struct userconf *ds __attribute__ ((unused)))
{
	int r = expected_uc_load;

	assert(r >= 0);
	expected_uc_load = -1;

	return r;
}

/* FIXME: replace this by a checker */
void
test_log_writen(int priority, const char **s)
{
	unsigned int i;

	printf("priority %i: ", priority);

	for (i = 0; s[i] != NULL; i++)
		printf("%s", s[i]);

	printf("\n");
}

int
main(void)
{
	struct {
		struct xmitstat xmitstat;
		const char *input;
		unsigned int bugoffset;
		unsigned int tls_verify:1;	/* call to tls_verify() is permitted */
		unsigned int badbounce:1;	/* if this is a bad bounce */
		unsigned int maxrcpt:1;		/* maximum number of rcpts should have been reached before */
		int tls_verify_result;
		int tarpit;
		int flush_rcpt;	/* clear the recipient list after this test */
		int rcpt_result;	/* expected result of smtp_rcpt() */
		int uc_load;
		const char *netmsg;
	} testdata[] = {
		/* simple acceptance */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
			},
			.input = "RCPT TO:<foo@example.org>",
			.uc_load = 0,
			.netmsg = "250 2.1.0 recipient <foo@example.org> OK\r\n",
		},
		/* all filters return temporary error */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
				.helostatus = 4,
				.spf = 4,
				.check2822 = 1
			},
			.input = "RCPT TO:<bar@example.org>",
			.uc_load = 0,
			.tarpit = 1,
			.netmsg = "450 4.7.0 mail temporary denied for policy reasons\r\n"
		},
		/* fail_hard_on_temp, all filters but one pass, that one is temp */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
				.helostatus = 4
			},
			.input = "RCPT TO:<xfx@example.org>",
			.uc_load = 0,
			.tarpit = 1,
			.netmsg = "550 5.7.1 mail denied for policy reasons\r\n"
		},
		/* permanent rejection */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
				.helostatus = 2
			},
			.input = "RCPT TO:<bar@example.org>",
			.uc_load = 0,
			.tarpit = 1,
			.netmsg = "550 5.7.1 mail denied for policy reasons\r\n"
		},
		/* permanent rejection, user pretends to not exist */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
				.helostatus = 2
			},
			.input = "RCPT TO:<xxn@example.org>",
			.uc_load = 0,
			.tarpit = 1,
			.netmsg = "550 5.1.1 no such user <xxn@example.org>\r\n"
		},
		/* fail_hard_on_temp + nonexist_on_block, all filters but one pass, that one is temp */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
				.helostatus = 4
			},
			.input = "RCPT TO:<xfn@example.org>",
			.uc_load = 0,
			.tarpit = 1,
			.netmsg = "550 5.1.1 no such user <xfn@example.org>\r\n"
		},
		/* fail_hard_on_temp + nonexist_on_block, but whitelisted even if there is a temporary error */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
				.spf = 4,
				.helostatus = 5
			},
			.input = "RCPT TO:<xfn@example.org>",
			.uc_load = 0,
			.tarpit = 1,
			.netmsg = "250 2.1.0 recipient <xfn@example.org> OK\r\n"
		},
		/* fail_hard_on_temp + nonexist_on_block, all filters but one pass, that one is error */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
				.helostatus = 7
			},
			.input = "RCPT TO:<xxx@example.org>",
			.uc_load = 0,
			.tarpit = 1,
			.netmsg = "450 4.7.0 mail temporary denied for policy reasons\r\n"
		},
		/* user does not exist */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
			},
			.input = "RCPT TO:<nothere@example.org>",
			.tarpit = 1,
			.rcpt_result = EBOGUS
			/* no netmsg, it would be written by addrparse() */
		},
		/* remote user, relaying denied */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
			},
			.input = "RCPT TO:<abc@example.com>",
			.tarpit = 1,
			.tls_verify = 1,
			.rcpt_result = EBOGUS,
			.netmsg = "551 5.7.1 relaying denied\r\n"
		},
		/* remote user, relaying permitted */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
			},
			.input = "RCPT TO:<abc@example.com>",
			.flush_rcpt = 1,
			.tls_verify = 1,
			.tls_verify_result = 1,
			.netmsg = "250 2.1.0 recipient <abc@example.com> OK\r\n"
		},
		/* first one of a multi-recipient bounce, this one with space bug */
		{
			.input = "rcpt to:  <foo@example.org>",
			.bugoffset = 2,
			.netmsg = "250 2.1.0 recipient <foo@example.org> OK\r\n",
		},
		/* this is the one that gets immediate rejection */
		{
			.input = "RCPT TO:  <foo@example.org>",
			.bugoffset = 2,
			.tarpit = 1,
			.rcpt_result = EBOGUS,
			.badbounce = 1,
			.netmsg = "550 5.5.3 bounce messages must not have more than one recipient\r\n"
		},
		/* once again because of it's beauty */
		{
			.input = "RCPT TO: <foo@example.org>",
			.bugoffset = 1,
			.tarpit = 1,
			.rcpt_result = EBOGUS,
			.badbounce = 1,
			.flush_rcpt = 1,
			.netmsg = "550 5.5.3 bounce messages must not have more than one recipient\r\n"
		},
		/* maximum number of recipients reached */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
			},
			.input = "RCPT TO:<abc@example.org>",
			.flush_rcpt = 1,
			.maxrcpt = 1,
			.netmsg = "452 4.5.3 Too many recipients\r\n"
		},
		/* space bug, rcpt to not in angle brackets */
		{
			.input = "rcpt to: postmaster",
			.flush_rcpt = 1,
			.tarpit = 1,
			.rcpt_result = EINVAL,
			.netmsg = "500 5.5.2 command syntax error\r\n"
		},
		{
			.input = NULL
		}
	};
	unsigned int i;

	TAILQ_INIT(&head);

	testcase_setup_net_writen(testcase_net_writen_combine);
	testcase_setup_netnwrite(testcase_netnwrite_compare);
	testcase_setup_log_writen(test_log_writen);

	for (i = 0; testdata[i].input != NULL; i++) {
		int r;
		unsigned int oldgood = goodrcpt;
		unsigned int oldcnt = rcptcount;

		linein.len = strlen(testdata[i].input);
		assert(linein.len < TESTIO_MAX_LINELEN);

		/* initialize environment */
		strcpy(linein.s, testdata[i].input);
		xmitstat = testdata[i].xmitstat;
		expected_uc_load = testdata[i].uc_load;
		expected_bugoffset = testdata[i].bugoffset;
		expected_tarpit = testdata[i].tarpit;
		expected_tls_verify = testdata[i].tls_verify;
		tls_verify_result = testdata[i].tls_verify_result;
		netnwrite_msg = testdata[i].netmsg;
		if (testdata[i].maxrcpt)
			oldcnt = rcptcount = MAXRCPT;

		r = smtp_rcpt();

		if (r != testdata[i].rcpt_result) {
			fprintf(stderr, "%u: smtp_rcpt() returned %i instead of %i\n",
					i, r, testdata[i].rcpt_result);
			errcnt++;
		}

		if ((testdata[i].netmsg != NULL) && (testdata[i].netmsg[0] == '2')) {
			if (goodrcpt != oldgood + 1) {
				fprintf(stderr, "%u: smtp_rcpt() returned 0, but goodrcpt was %u instead of %u\n",
						i, goodrcpt, oldgood + 1);
				errcnt++;
			}
			if (rcptcount != oldcnt + 1) {
				fprintf(stderr, "%u: smtp_rcpt() returned 0, but rcptcount was %u instead of %u\n",
						i, rcptcount, oldcnt + 1);
				errcnt++;
			}
		} else {
			if (testdata[i].badbounce) {
				if (!badbounce) {
					fprintf(stderr, "%u: bad bounce expected, but not set by smtp_rcpt()\n",
							i);
					errcnt++;
				}
				if (goodrcpt != 0) {
					fprintf(stderr, "%u: goodrcpt was %u instead of 0 for bad bounce\n",
							i, goodrcpt);
					errcnt++;
				}
			} else if (goodrcpt != oldgood) {
				fprintf(stderr, "%u: smtp_rcpt() returned %i, but goodrcpt was %u instead of %u\n",
						i, r, goodrcpt, oldgood);
				errcnt++;
			}
		}

		if (xmitstat.spacebug != !!testdata[i].bugoffset) {
				fprintf(stderr, "%u: smtp_rcpt() set spacebug to %u, but %u was expected\n",
						i, xmitstat.spacebug, !!testdata[i].bugoffset);
				errcnt++;
		}

		/* flush on request and on last test */
		if (testdata[i].flush_rcpt || (testdata[i + 1].input == NULL)) {
			while (!TAILQ_EMPTY(&head)) {
				struct recip *l = TAILQ_FIRST(&head);

				TAILQ_REMOVE(&head, TAILQ_FIRST(&head), entries);
				free(l->to.s);
				free(l);
			}
			goodrcpt = 0;
			rcptcount = 0;
			badbounce = 0;
		}
	}

	return errcnt;
}
