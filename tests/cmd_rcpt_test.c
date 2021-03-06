#include <qsmtpd/commands.h>

#include <fmt.h>
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
string heloname = {
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

void
freeips(struct ips *x)
{
	assert(x == NULL);
}

/* checker functions */
int
addrparse(char *in, const int flags, string *addr, char **more, struct userconf *ds, const char *rh, const off_t rs)
{
	assert(rh == rcpthosts);
	assert(rs == rcpthsize);
	assert(flags == 1);

	assert(in == linein.s + 9 + expected_bugoffset);

	*more = NULL;

	char *br = strchr(in, '>');
	assert(br != NULL);

	int i = newstr(addr, br - in + 1);
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

int
find_servercert(const char *localport __attribute__((unused)))
{
	abort();
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

int
test_ask_dnsmx(const char *domain, struct ips **ips)
{
	if (strcmp(domain, "example.com") == 0) {
		*ips = NULL;
		return 0;
	}

	if (strcmp(domain, "neverthere.example.com") == 0) {
		*ips = NULL;
		return 2;
	}

	return 1;
}

static const char *second_log_write_msg;
static int second_log_write_prio;

void
test_log_write(int priority, const char *msg)
{
	testcase_log_write_compare(priority, msg);

	log_write_msg = second_log_write_msg;
	log_write_priority = second_log_write_prio;
	second_log_write_msg = NULL;
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
		const char *netmsg;	/* expected network message */
		const char *logmsg1;	/* first expected log message */
		const char *logmsg2;	/* second expected log message */
		int log_prio1;		/* first expected log priority */
		int log_prio2;		/* second expected log priority */
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
			.tarpit = 1,
			.netmsg = "450 4.7.0 mail temporary denied for policy reasons\r\n",
			.logmsg1 = "temporarily rejected message to <bar@example.org> from <baz@example.org> from IP [] {third filter, global policy}",
			.log_prio1 = LOG_INFO
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
			.tarpit = 1,
			.netmsg = "550 5.7.1 mail denied for policy reasons\r\n",
			.logmsg1 = "rejected message to <xfx@example.org> from <baz@example.org> from IP [] {third filter, global policy}",
			.log_prio1 = LOG_INFO
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
			.tarpit = 1,
			.netmsg = "550 5.7.1 mail denied for policy reasons\r\n",
			.logmsg1 = "rejected message to <bar@example.org> from <baz@example.org> from IP [] {second filter, domain policy}",
			.log_prio1 = LOG_INFO
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
			.tarpit = 1,
			.netmsg = "550 5.1.1 no such user <xxn@example.org>\r\n",
			.logmsg1 = "rejected message to <xxn@example.org> from <baz@example.org> from IP [] {second filter, domain policy}",
			.log_prio1 = LOG_INFO
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
			.tarpit = 1,
			.netmsg = "550 5.1.1 no such user <xfn@example.org>\r\n",
			.logmsg1 = "rejected message to <xfn@example.org> from <baz@example.org> from IP [] {third filter, global policy}",
			.log_prio1 = LOG_INFO
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
			.tarpit = 1,
			.netmsg = "450 4.7.0 mail temporary denied for policy reasons\r\n",
			.logmsg1 = "error 1024 in filter 1 for user xxx@example.org",
			.logmsg2 = "temporarily rejected message to <xxx@example.org> from <baz@example.org> from IP [] {third filter, global policy}",
			.log_prio1 = LOG_WARNING,
			.log_prio2 = LOG_INFO
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
			.rcpt_result = EBOGUS,
			.logmsg1 = "rejected message to <nothere@example.org> from <baz@example.org> from IP [] {no such user}",
			.log_prio1 = LOG_INFO
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
			.netmsg = "551 5.7.1 relaying denied\r\n",
			.logmsg1 = "rejected message to <abc@example.com> from <baz@example.org> from IP [] {relaying denied}",
			.log_prio1 = LOG_INFO
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
			.netmsg = "550 5.5.3 bounce messages must not have more than one recipient\r\n",
			.logmsg1 = "rejected message to <foo@example.org> from <> from IP [] {bad bounce}",
			.logmsg2 = "rejected message to <foo@example.org> from <> from IP [] {bad bounce}",
			.log_prio1 = LOG_INFO,
			.log_prio2 = LOG_INFO
		},
		/* once again because of it's beauty */
		{
			.input = "RCPT TO: <foo@example.org>",
			.bugoffset = 1,
			.tarpit = 1,
			.rcpt_result = EBOGUS,
			.badbounce = 1,
			.flush_rcpt = 1,
			.netmsg = "550 5.5.3 bounce messages must not have more than one recipient\r\n",
			.logmsg1 = "rejected message to <foo@example.org> from <> from IP [] {bad bounce}",
			.log_prio1 = LOG_INFO
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
			.rcpt_result = EINVAL
		},
		/* remote user, relaying permitted, but target domain not existent */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
			},
			.input = "RCPT TO:<abc@notthere.example.com>",
			.tls_verify = 1,
			.tls_verify_result = 1,
			.rcpt_result = EDONE,
			.netmsg = "451 4.4.3 cannot find a mail exchanger for notthere.example.com\r\n",
			.logmsg1 = "temporarily rejected message to <abc@notthere.example.com> from <baz@example.org> from IP [] {no target MX}",
			.log_prio1 = LOG_INFO
		},
		/* remote user, relaying permitted, target domain only publishes null MX */
		{
			.xmitstat = {
				.mailfrom = {
					.s = "baz@example.org",
					.len = strlen("baz@example.org")
				},
			},
			.input = "RCPT TO:<abc@neverthere.example.com>",
			.tls_verify = 1,
			.tls_verify_result = 1,
			.rcpt_result = EDONE,
			.netmsg = "556 5.1.10 only null MX exists for neverthere.example.com\r\n",
			.logmsg1 = "permanently rejected message to <abc@neverthere.example.com> from <baz@example.org> from IP [] {null target MX}",
			.log_prio1 = LOG_INFO
		},
		{ }
	};

	TAILQ_INIT(&head);

	testcase_setup_ask_dnsmx(test_ask_dnsmx);
	testcase_setup_net_writen(testcase_net_writen_combine);
	testcase_setup_netnwrite(testcase_netnwrite_compare);
	testcase_setup_log_writen(testcase_log_writen_combine);
	testcase_setup_log_write(test_log_write);

	for (unsigned int i = 0; testdata[i].input != NULL; i++) {
		unsigned int oldgood = goodrcpt;
		unsigned int oldcnt = rcptcount;
		char ulbuf[ULSTRLEN];

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
		log_write_msg = testdata[i].logmsg1;
		log_write_priority = testdata[i].log_prio1;
		second_log_write_msg = testdata[i].logmsg2;
		second_log_write_prio = testdata[i].log_prio2;
		if (testdata[i].maxrcpt)
			oldcnt = rcptcount = MAXRCPT;

		int r = smtp_rcpt();

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

		snprintf(ulbuf, sizeof(ulbuf), "%u", i);
		errcnt += testcase_netnwrite_check(ulbuf);

		if (log_write_msg != NULL) {
			fprintf(stderr, "%u: smtp_rcpt() did not write the expected log string '%s'\n",
					i, log_write_msg);
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
		}
	}

	return errcnt;
}
