#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define VERSION "0.01"

static char linein[256];

static struct params {
	char *name;
	unsigned int len;
	long value;
} params[] = {
	{ .name = "whitelistauth", .len = 13, .value = 0 },
	{ .name = "forcestarttls", .len = 13, .value = 0 },
	{ .name = "nobounce", .len = 8, .value = 0 },
	{ .name = "check_strict_rfc2822", .len = 20, .value = 0 },
	{ .name = "fromdomain", .len = 10, .value = 0 },
	{ .name = "reject_ipv6only", .len = 15, .value = 0 },
	{ .name = "helovalid", .len = 9, .value = 0 },
	{ .name = "block_SoberG", .len = 12, .value = 0 },
	{ .name = "spfpolicy", .len = 9, .value = 0 },
	{ .name = "usersize", .len = 8, .value = 0 },
	{ .name = "fail_hard_on_temp", .len = 17, .value = 0 },
	{ .name = "nonexist_on_block", .len = 17, .value = 0 },
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
	syslog(LOG_ERR, "%s\n", s);
}

static void
err2(const char *s, const char *t)
{
	printf("ERROR: %s%s\n", s, t);
	syslog(LOG_ERR, "%s%s\n", s, t);
}

static void __attribute__ ((noreturn))
eXit(void)
{
	closelog();
	exit(0);
}

static int
warn_noparam(const int index, const char *cmd)
{
	if (linein[index] != '\n') {
		fputs("error: command \"", stdout);
		fputs(cmd, stdout);
		puts("\" takes no parameters");
		commstat = EINVAL;
		return 1;
	}
	return 0;
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
	int len = 0;

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
	if (fclose(fcfd))
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
	warn_noparam(4, "quit");
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
	if (warn_noparam(4, "show"))
		return;

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

static void
wr(void)
{
	if (warn_noparam(5, "write"))
		return;
	writefc();
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
				tmp = strtol(linein + 5 + params[i].len, &r, 0);
				if (*r != '\n') {
					printf("ERROR: can't parse second argument as integer\n");
					commstat = EINVAL;
					return;
				}
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
}

struct addrlist {
	TAILQ_ENTRY(addrlist) entries;	/* List. */
	char *address;
};

struct edbuf {
	const char *name;
	union {
		struct {
			char *mem;				/* for IPv4/IPv6 maps */
			unsigned int len;			/* length of map */
		} map;
		TAILQ_HEAD(addrlhead, addrlist) lhead;	/* list of addresses/domain/blacklists */
	} buf;
} editbuffer;

static int
editread(const int type)
{
	if (type <=2 ) {
		FILE *fcfd;

		TAILQ_INIT(&editbuffer.buf.lhead);
		
	} else {
		int fd;
		struct stat st;

		editbuffer.buf.map.mem = NULL;
		editbuffer.buf.map.len = 0;
		if ( (fd = open(editbuffer.name, O_RDONLY)) < 0) {
			if (errno != ENOENT) {
				commstat = errno;
				err2("opening file failed: ", editbuffer.name);
				return 1;
			} else {
				commstat = 0;
				return 0;
			}
		}
		if (flock(fd,LOCK_SH)) {
			commstat = errno;
			close(fd);
			err2("cannot lock input file: ", editbuffer.name);
			return 1;
		}
		if (fstat(fd, &st)) {
			commstat = errno;
			return 1;
		}
		if (!st.st_size) {
			close(fd);
			commstat = 0;
			return 0;
		}

		if (st.st_size % (type == 3) ? 5 : 17) {
			err2("file has wrong length for this type of file: ", editbuffer.name);
			close(fd);
			return 1;
		}
		editbuffer.buf.map.mem = malloc(st.st_size);
		if (!editbuffer.buf.map.mem) {
			close(fd);
			err("out of memory");
			commstat = ENOMEM;
			return 1;
		}

		off_t len = 0;

		while (len < st.st_size) {
			int i;

			if ( (i = read(fd, editbuffer.buf.map.mem + len, st.st_size - len)) < 0) {
				commstat = errno;
				free(editbuffer.buf.map.mem);
				editbuffer.buf.map.mem = NULL;
				err2("error reading from file ", editbuffer.name);
				return 1;
			}
			len += i;
		}
		editbuffer.buf.map.len = st.st_size;
		close(fd);
	}
	commstat = 0;
	return 0;
}

static void
editquit(void)
{
	if (warn_noparam(4, "quit"))
		return;
}

struct ecommands {
	const char *name;
	const unsigned int len;
	void (*func)(int);
} edcmds[] = {
	{ .name = "write", .len = 5, .func = NULL },
	{ .name = "add", .len = 3, .func = NULL },
	{ .name = "exit", .len = 4, .func = eXit },
	{ .name = "quit", .len = 4, .func = editquit },
	{ .name = NULL }
};

static void
edit(void)
{
	struct editfiles {
		char *name;
		unsigned int len;
		int type;	/* 0: address 1: domain 2: blacklist 3: IPv4 match 4: IPv6 match */
	} efiles[] = {
		{ .name = "badcc", .len = 5, .type = 0 },
		{ .name = "badmailfrom", .len = 11, .type = 0 },
		{ .name = "goodmailfrom", .len = 12, .type = 0 },
		{ .name = "dnsbl", .len = 5, .type = 2 },
		{ .name = "whitednsbl", .len = 10, .type = 2 },
		{ .name = "dnsblv6", .len = 7, .type = 2 },
		{ .name = "whitednsblv6", .len = 12, .type = 2 },
		{ .name = "badhelo", .len = 7, .type = 1 },
		{ .name = "ipbl", .len = 4, .type = 3 },
		{ .name = "ipwl", .len = 4, .type = 3 },
		{ .name = "ipblv6", .len = 6, .type = 4 },
		{ .name = "ipwlv6", .len = 6, .type = 4 },
		{ .name = "rspf", .len = 4, .type = 2 },
		{ .name = "spfstrict", .len = 9, .type = 1 },
		{ .name = "ignorespf", .len = 9, .type = 1 },
		{ .name = "namebl", .len = 6, .type = 2 },
		{ .name = NULL }
	};
	int index;
	struct editfiles *active;

	if (linein[4] == '\n') {
		puts("Syntax: edit <FILENAME>");
		commstat = EINVAL;
		return;
	}

	unsigned int l = strlen(linein + 5) - 1;

	for (index = 0; efiles[index].name; index++) {
		if (l != efiles[index].len)
			continue;
		if (!strncmp(linein + 5, efiles[index].name, l))
			break;
	}
	if (!efiles[index].name) {
		if ((l == 4) && !strncmp(linein + 5, "help", 4)) {
			const char *typenames[] = { "address", "domain", "blacklist", "IPv4 match", "IPv6 match" };

			for (index = 0; efiles[index].name; index++) {
				printf("\t%s\t{type: %s}\n", efiles[index].name, typenames[efiles[index].type]);
			}
			commstat = 0;
		} else {
			puts("unknown file");
			commstat = EINVAL;
		}
		return;
	}

	active = efiles + index;

	editbuffer.name = active->name;

	if (editread(active->type))
		return;

	do {
		fprintf(stdout, "fc <%s> > ", active->name);
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
				edcmds[i].func(active->type);
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

static struct commands {
	const char *name;
	const unsigned int len;
	void (*func)(void);
} cmds[] = {
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
