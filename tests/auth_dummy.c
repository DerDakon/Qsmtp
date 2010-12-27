#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "auth_users.h"

static void
readData(char *buf, const size_t len)
{
	size_t pos = 0;

	do {
		ssize_t res = read(3, buf + pos, 1);
		if (res < 0)
			exit(errno);
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
	unsigned int i = 0;

	if (argc != 2)
		return EINVAL;

	if (strcmp(argv[1], autharg) != 0)
		return EINVAL;

	readData(user, sizeof(user));
	readData(pass, sizeof(pass));
	readData(resp, sizeof(resp));

	while (users[i].username != NULL) {
		if ((strcmp(users[i].username, user) == 0) &&
				(strcmp(users[i].password, pass) == 0))
			return 0;

		i++;
	}

	return 1;
}
