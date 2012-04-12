#include "../qsmtpd/data.c"

#include <stdio.h>
#include <time.h>

int relayclient;
unsigned long sslauth;
unsigned long databytes;
unsigned int goodrcpt;
int badbounce;
struct xmitstat xmitstat;
char *protocol;
const char *auth_host;
const char *auth_check;
const char **auth_sub;
const char **globalconf;
string heloname;
string msgidhost;
string liphost;
int socketd = 1;
long comstate = 0x001;
int authhide;
int submission_mode;

struct recip *thisrecip;

struct smtpcomm commands[8];

// override this so always the same time is returned for testcases
static time_t testtime;

time_t
time(time_t *t __attribute__ ((unused)))
{
	return testtime;
}

pid_t
fork_clean()
{
	return -1;
}

void
freedata(void)
{
}

void
tarpit(void)
{
}

void
sync_pipelining(void)
{
}

int
spfreceived(int fd __attribute__ ((unused)), const int spf __attribute__ ((unused)))
{
	return -1;
}

static int
check_twodigit(void)
{
	int ret = 0;
	int i;

	for (i = 0; i < 100; i++) {
		char mine[3];
		char other[3];

		snprintf(other, sizeof(other), "%02i", i);
		two_digit(mine, i);
		mine[2] = '\0';

		if (strcmp(mine, other)) {
			ret++;

			fprintf(stderr, "two_digit(%i) = %s\n", i, mine);
		}
	}

	return ret;
}

static int
check_date822(void)
{
	char buf[32];
	const char *expt[] = { "Thu, 01 Jan 1970 00:00:00 +0000",
			"Wed, 11 Apr 2012 18:32:17 +0200" };
	const time_t testtimes[] = { 0, 1334161937 };
	const char *tzones[] = { "TZ=UTC", "TZ=CET" };
	int ret = 0;
	int i;
	char tzbuf[12];

	memset(buf, 0, sizeof(buf));

	for (i = 0; i < 2; i++) {
		testtime = testtimes[i];
		memcpy(tzbuf, tzones[i], strlen(tzones[i]) + 1);
		putenv(tzbuf);
		date822(buf);

		if (strcmp(buf, expt[i])) {
			ret++;
			fprintf(stderr, "time %li was encoded to '%s' instead of '%s'\n",
					(long) testtimes[i], buf, expt[i]);
		}
	}

	return ret;
}

int main()
{
	int ret = 0;

	memset(&xmitstat, 0, sizeof(xmitstat));

	ret += check_twodigit();
	ret += check_date822();

	return ret;
}
