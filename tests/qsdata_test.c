#include "../qsmtpd/data.c"

#include <stdio.h>

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
check_twodigit()
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

int main()
{
	int ret = 0;

	memset(&xmitstat, 0, sizeof(xmitstat));

	ret += check_twodigit();

	return ret;
}
