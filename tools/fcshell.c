#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define VERSION "0.01"

static char linein[256];

static struct params {
	char *name;
	unsigned int len;
	long value;
} params[] = {
	{ .name = "whitelistauth", .len = 13, .value = 0 },
	{ .name = "forcestarttls", .len = 13, .value = 0 },
	{ .name = NULL }
};

static int commstat;		/* status of the last command, for use in "echo $?" */

static void
dolog(const char *s)
{
	syslog(LOG_INFO, "%s\n", s);
}

static void
err(const char *s)
{
	printf("ERROR: %s\n", s);
	dolog(s);
}

static void __attribute__ ((noreturn))
eXit(void)
{
	closelog();
	exit(0);
}

static void
readfc(void)
{
	FILE *fcfd;
	char inp[64];
	unsigned int len;

	for (int i = 0; params[i].name; i++) {
		params[i].value = 0;
	}
	fcfd = fopen("filterconf", "r");
	if (fcfd == NULL) {
		commstat = (errno == ENOENT) ? 0 : errno;
		return;
	}
	while (fgets(inp, sizeof(inp), fcfd)) {
		len = strlen(inp);
		if (inp[len - 1] != '\n') {
			do {
				if (!fgets(inp, sizeof(inp), fcfd))
					goto out;
				
			} while (inp[strlen(inp) - 1] != '\n');
		}
		if (inp[0] == '#')
			continue;
		for (int i = 0; params[i].name; i++) {
			if (!strncmp(inp, params[i].name, params[i].len)) {
				if (inp[params[i].len] == '=') {
					char *r;
					long tmp;

					tmp = strtol(inp + params[i].len + 1, &r, 10);
					if (*r == '\n') {
						/* silently ignore all errors here */
						params[i].value = tmp;
						break;
					}
				}
			}
		}
	}
out:
	fclose(fcfd);
	commstat = 0;
}

static void
writefc(void)
{
	FILE *fcfd;
	char fn[25];
	int e;
	int len;

	snprintf(fn, sizeof(fn), "filterconf.%i", getpid());
	fcfd = fopen(fn, "w");
	if (!fcfd) {
		commstat = errno;
		err("can't create filterconf tempfile");
		return;
	}

	for (int i = 0; params[i].name; i++) {
		if (params[i].value) {
			if (fprintf(fcfd, "%s=%li\n", params[i].name, params[i].value) < 0)
				goto err;
			len = 1;
		}
	}
	while ( (e = fclose(fcfd)) && (errno == EINTR));
	if (e)
		goto err;
	if (!len) {
		/* nothing in the file */
		if (unlink(fn)) {
			err("error removing empty tempfile");
		}
		if (unlink("filterconf")) {
			if (errno != ENOENT) {
				commstat = errno;
				err("cannot remove old filterconf file");
				return;
			}
		}
	} else {
		if (rename(fn, "filterconf")) {
			commstat = errno;
			err("can't rename tempfile to filterconf");
			return;
		}
	}
	commstat = 0;
	return;
err:
	commstat = errno;
	fclose(fcfd);
	err("error writing to filterconf tempfile");
}

static void __attribute__ ((noreturn))
quit(void)
{
	writefc();
	eXit();
}

static void
echo(void)
{
	if (!linein[4]) {
		commstat = (puts("") == EOF) ? errno : 0;
	} else if (!strcmp(linein, "echo $?\n")) {
		if (printf("%i\n", commstat) < 0) {
			commstat = errno;
		} else {
			commstat = 0;
		}
	} else if (!strcmp(linein, "echo $VERSION")) {
		if (puts("fcshell " VERSION) == EOF) {
			commstat = errno;
		} else {
			commstat = 0;
		}
	} else {
		if (printf("%s", linein + 5) < 0) {
			commstat = errno;
		} else {
			commstat = 0;
		}
	}
}

static void
show(void)
{
	for (int i = 0; params[i].name; i++) {
		if (printf("%s=%li\n", params[i].name, params[i].value) < 0)
			goto err;
	}
	commstat = 0;
	return;
err:
	commstat = errno;
	dolog("error on show");
	puts("WARNING: an error occured");
}

struct commands {
	const char *name;
	unsigned int len;
	void (*func)(void);
};

static void
wr(void)
{
	if (linein[5] != '\n') {
		puts("ERROR: command \"write\" takes no parameters, data NOT written");
		commstat = EINVAL;
		return;
	}
	writefc();
}

static void
editquit(void) {
	if (linein[4] != '\n') {
		puts("unrecognized command");
		commstat = EINVAL;
		linein[1] = '\0';
	}
}

static struct commands edcmds[] = {
	{ .name = "write", .len = 5, .func = NULL },
	{ .name = "add", .len = 3, .func = NULL },
	{ .name = "exit", .len = 4, .func = eXit },
	{ .name = "quit", .len = 4, .func = editquit },
	{ .name = NULL }
};

static void
edit(void)
{
	char fn[32];

	if (linein[4] == '\n') {
		puts("Syntax: edit <FILENAME>");
		commstat = EINVAL;
		return;
	}

	unsigned int l = strlen(linein + 5) - 1;
	memcpy(fn, linein + 5, l);
	fn[l] = '\0';

	do {
		fprintf(stdout, "fc <%s> > ", fn);
		if (!fgets(linein, sizeof(linein), stdin)) {
			puts("");
			eXit();
		}
		if (linein[strlen(linein) - 1] != '\n') {
			puts("input line too long");
			while (fgets(linein, sizeof(linein), stdin)) {
				if (linein[strlen(linein) - 1] == '\n')
					break;
			}
			/* error are not caught */
			continue;
		}

		unsigned int i = 0;
		int error = 1;

		while (edcmds[i].name) {
			if (!strncmp(linein, edcmds[i].name, edcmds[i].len)) {
				if ((linein[edcmds[i].len] != '\n') && (linein[edcmds[i].len] != ' '))
					break;
				edcmds[i].func();
				error = 0;
				break;
			}
			i++;
		}
		if (error) {
			puts("unrecognized command");
			commstat = EINVAL;
		}
	} while (strcmp(linein, "quit\n"));
}

static void
set(void)
{
	int error = 1;

	if (linein[3] == '\n') {
		puts("SYNTAX: set <PARAMETER> [<VALUE>]");
		commstat = EINVAL;
		return;
	}
	for (int i = 0; params[i].name; i++) {
		if (!strncmp(linein + 4, params[i].name, params[i].len)) {
			char *r;
			int tmp;
	
			if (linein[4 + params[i].len] == '\n') {
				tmp = 0;
			} else {
				if (linein[4 + params[i].len] != ' ') {
					break;
				}
				tmp = strtol(linein + 17, &r, 0);
				if (*r != '\n')
					goto err;
			}
			params[i].value = tmp;
			printf("setting %s to %i (hex 0x%x)\n", params[i].name, tmp, tmp);
			error = 0;
			break;
		}
	}
	if (error) {
		puts("ERROR: unknown parameter");
		commstat = EINVAL;
	}
	return;
err:
	printf("ERROR: can't parse second argument as integer\n");
	commstat = EINVAL;
}

static struct commands cmds[] = {
	{ .name = "echo", .len = 4, .func = echo },
	{ .name = "quit", .len = 4, .func = quit },
	{ .name = "exit", .len = 4, .func = eXit },
	{ .name = "show", .len = 4, .func = show },
	{ .name = "auth", .len = 4, .func = NULL },
	{ .name = "edit", .len = 4, .func = edit },
	{ .name = "write", .len = 5, .func = wr },
	{ .name = "set", .len = 3, .func = set },
	{ .name = NULL }
};

int
main(void)
{
	openlog("fcshell", LOG_PID, LOG_LOCAL1);
	readfc();
	if (commstat) {
		dolog("can't open filterconf");
	}
	while (1) {
		fputs("fc > ", stdout);
		if (!fgets(linein, sizeof(linein), stdin)) {
			puts("");
			eXit();
		}
		if (linein[strlen(linein) - 1] != '\n') {
			puts("input line too long");
			while (fgets(linein, sizeof(linein), stdin)) {
				if (linein[strlen(linein) - 1] == '\n')
					break;
			}
			/* error are not caught */
			continue;
		}

		unsigned int i = 0;
		int error = 1;

		while (cmds[i].name) {
			if (!strncmp(linein, cmds[i].name, cmds[i].len)) {
				if ((linein[cmds[i].len] != '\n') && (linein[cmds[i].len] != ' '))
					break;
				cmds[i].func();
				error = 0;
				break;
			}
			i++;
		}
		if (error) {
			puts("unrecognized command");
			commstat = EINVAL;
		}
	}
}
