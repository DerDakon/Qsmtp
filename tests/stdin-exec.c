#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

// change stdin, then exec
// the first arguments defines what happens with stdin
// -(empty): stdin is closed
// -'s': an unconnected socket
// -everything else: filename to open (read only)
// the second argument is the file to execute
// all other arguments are passed to the new binary
int
main(int argc, char **argv)
{
	if (argc < 3)
		abort();

	close(0);

	if (strlen(argv[1]) == 0) {
		// fine, keep it closed
	} else {
		int fd;
		if (strcmp(argv[1], "s") == 0) {
			fd = socket(AF_UNIX, SOCK_STREAM, 0);
		} else
			fd = open(argv[1], O_RDONLY);

		// make sure this isn't accidentially an error code of the other binary
		if (fd < 0)
			abort();

		if (fd != 0) {
			if (dup2(fd, 0) != 0)
				abort();
			close(fd);
		}
	}

	return execve(argv[2], argv + 2, NULL);
}
