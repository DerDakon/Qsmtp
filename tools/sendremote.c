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

	execve("./qremote/Qremote", argv + 1, NULL);

	return 0;
}
