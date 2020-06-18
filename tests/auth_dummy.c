#include "auth_users.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
readData(char *buf, const size_t len)
{
	size_t pos = 0;

	do {
		ssize_t res = read(3, buf + pos, 1);
		if (res == -1)
			exit(errno);
		if (res == 0)
			exit(EINVAL);
		pos++;
	} while ((pos < len) && (buf[pos - 1] != '\0'));

	if (buf[pos - 1] != '\0')
		exit(EINVAL);
}

int main(int argc, const char **argv)
{
	char user[1024];
	char pass[1024];
	char resp[1024];

	if (argc != 2)
		return EINVAL;

	if (strcmp(argv[1], autharg) != 0)
		return EINVAL;

	readData(user, sizeof(user));
	readData(pass, sizeof(pass));
	readData(resp, sizeof(resp));

	if (strcmp(users[0].username, user) == 0)
		abort();

	if (strlen(resp) != 0)
		return 1;

	for (unsigned int i = 1; users[i].username != NULL; i++) {
		if ((strcmp(users[i].username, user) == 0) &&
				(strcmp(users[i].password, pass) == 0))
			return 0;
	}

	return 1;
}
