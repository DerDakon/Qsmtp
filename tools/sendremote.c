#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int fd;

	if (argc < 4) {
		fprintf(stderr, "%s needs at least 4 arguments:\n", argv[0]);
		fprintf(stderr, "  /file/to/send target_domain from_address recipient [recipients ...]\n");
		return EINVAL;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		fd = errno;
		fprintf(stderr, "error %i opening %s\n", fd, argv[1]);
		return fd;
	}

	if (dup2(fd, 0) != 0) {
		fprintf(stderr, "cannot change the file descriptor\n");
		close(fd);
		return 1;
	}

	for (fd = 1; fd < argc - 1; fd++)
		argv[fd] = argv[fd + 1];
	argv[argc - 1] = NULL;
	argv[0] = "./qremote/Qremote";

	execve(argv[0], argv, NULL);

	return 0;
}
