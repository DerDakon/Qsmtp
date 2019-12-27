/** \file fcshell.c
 \brief shell program to allow a user to modify his filterconf setting from remote host
 */

#define _POSIX_C_SOURCE 200809L /* for O_CLOEXEC */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#define VERSION "0.02"

static char linein[300];

static struct {
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
	{ .name = "block_wildcardns", .len = 16, .value = 0 },
	{ .name = "fail_hard_on_temp", .len = 17, .value = 0 },
	{ .name = "nonexist_on_block", .len = 17, .value = 0 },
	{ .name = NULL }
};

static int commstat;		/**< status of the last command, for use in "echo $?" */

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

static void
oom(void)
{
	err("out of memory");
	commstat = ENOMEM;
}

static void __attribute__ ((noreturn))
eXit(void)
{
	closelog();
	exit(0);
}

static void __attribute__ ((noreturn))
eXiT(int __attribute__ ((unused)) ignored)
{
	eXit();
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
				if (!fgets(inp, sizeof(inp), fcfd)) {
					fclose(fcfd);
					commstat = 0;
					return;
				}

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

	if (fclose(fcfd)) {
		fcfd = NULL;
		goto err;
	}

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
	if (fcfd != NULL)
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
eecho(int __attribute__ ((unused)) type)
{
	echo();
}

static void
show(void)
{
	if (warn_noparam(4, "show"))
		return;

	for (int i = 0; params[i].name; i++) {
		if (printf("%s=%li\n", params[i].name, params[i].value) < 0) {
			commstat = errno;
			dolog("error on show");
			puts("WARNING: an error occured");
			return;
		}
	}
	commstat = 0;
	return;
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

struct {
	const char *name;
	union {
		struct {
			char *mem;			/**< for IPv4/IPv6 maps */
			unsigned int len;		/**< length of map */
		} map;
		TAILQ_HEAD(, addrlist) lhead;	/**< list of addresses/domain/blacklists */
	} buf;
} editbuffer;

static int
editread(const int type)
{
	if (type <= 2) {
		FILE *fcfd;

		TAILQ_INIT(&editbuffer.buf.lhead);

		fcfd = fopen("filterconf", "r");
		if (fcfd == NULL) {
			commstat = (errno == ENOENT) ? 0 : errno;
			return commstat;
		}
		while (fgets(linein, sizeof(linein), fcfd)) {
			unsigned int len = strlen(linein);
			struct addrlist *ad;

			if (!len || (linein[0] == '#') || (linein[0] == '\n'))
				continue;
			if (len >= 256) {
				err2("ignoring line with more than 256 characters in file ", editbuffer.name);
				while (linein[len] != '\n') {
					if (!fgets(linein, sizeof(linein), fcfd)) {
						fclose(fcfd);
						return 0;
					}
					len = strlen(linein);
				}
			}
			ad = malloc(sizeof(*ad));
			if (!ad || !(ad->address = malloc(len))) {
				fclose(fcfd);
				oom();
				return 1;
			}
			memcpy(ad->address, linein, --len);
			ad->address[len] = '\0';
			TAILQ_INSERT_TAIL(&editbuffer.buf.lhead, ad, entries);
		}
		fclose(fcfd);
		return 0;
	} else {
		int fd;
		struct stat st;

		editbuffer.buf.map.mem = NULL;
		editbuffer.buf.map.len = 0;
		if ( (fd = open(editbuffer.name, O_RDONLY | O_CLOEXEC)) < 0) {
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
			close(fd);
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
			oom();
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
				close(fd);
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
editwrite(const int type)
{
	FILE *fcfd;
	char fn[12 + strlen(editbuffer.name)];

	if (warn_noparam(5, "write"))
		return;

	if (((type <= 2) && !TAILQ_EMPTY(&editbuffer.buf.lhead)) || ((type > 2) && editbuffer.buf.map.len)) {

		snprintf(fn, sizeof(fn), "%s.%i", editbuffer.name, getpid());
		fcfd = fopen(fn, "w");
		if (!fcfd) {
			commstat = errno;
			err2("can't create tempfile ", fn);
			return;
		}

		switch (type) {
		case 0:
		case 1:
		case 2:
			{
			struct addrlist *thisad;
			TAILQ_FOREACH(thisad, &editbuffer.buf.lhead, entries)
				if (fprintf(fcfd, "%s\n", thisad->address) < 0)
					goto err;
			}
			break;
		case 3:
		case 4:	for (unsigned int i = 0; i < editbuffer.buf.map.len; i++) {
				if (fprintf(fcfd, "%c", editbuffer.buf.map.mem[i]) != 1)
					goto err;
			}
			break;
		}

		if (fclose(fcfd)) {
			fcfd = NULL;
			goto err;
		}

		if (rename(fn, editbuffer.name)) {
			commstat = errno;
			err2("can't rename tempfile to ", editbuffer.name);
			return;
		}
	} else {
		/* nothing in the file */
		if (unlink(editbuffer.name)) {
			if (errno != ENOENT) {
				commstat = errno;
				err2("cannot remove old file", editbuffer.name);
				return;
			}
		}
	}
	commstat = 0;
	return;
err:
	commstat = errno;
	if (fcfd != NULL)
		fclose(fcfd);
	err2("error writing to tempfile ", fn);
}

static void
editquit(const int type)
{
	if (warn_noparam(4, "quit"))
		return;
	linein[5] = '\n';
	editwrite(type);
}

static void
editadd(const int type)
{
	if (strchr(linein + 4, ' ')) {
		puts("ERROR: command \"add\" only takes one parameter");
		commstat = EINVAL;
		return;
	}

	switch (type) {
	case 0:
	case 1:
	case 2:	{
			struct addrlist *newad = malloc(sizeof(*newad));
			unsigned int len = strlen(linein + 4);
			linein[3 + len--] = '\0';

#warning FIXME: some error handling for parameter is missing here
			switch (type) {
			case 2:	if (!strchr(linein + 4, '.'))
					goto parse;
			case 1:	if (strchr(linein + 4, '@'))
					goto parse;
			case 0:	{
					char *tmp;

					/* this is allowed neither in domain nor in localpart
					 * even if a single '.' is allowed in both */
					if (strstr(linein + 4, ".."))
						goto parse;
					tmp = strchr(linein + 4, '@');
					if (tmp) {
/* check localpart */
						char *l = linein + 4;

						while (l < tmp) {
							if ((*l < 32) || (*l >= 127))
								goto parse;
							l++;
						}
						tmp++;
					} else {
						tmp = linein + 4;
					}
/* check domain */
					while (*tmp) {
						if ((*tmp < 46) || (*tmp == '/') || ((*tmp >= 58) && (*tmp <= 64)) ||
								((*tmp >= 91) && (*tmp <= 96)) || (*tmp > 'z'))
							goto parse;
						tmp++;
					}
				}
			}
			if (!newad)
				goto nomem;
			newad->address = malloc(len);
			if (!newad->address) {
				free(newad);
				goto nomem;
			}
			memcpy(newad->address, linein + 4, len);
			TAILQ_INSERT_TAIL(&editbuffer.buf.lhead, newad, entries);
		}
		break;
	case 3: {
			char *newbuf;
			char *net;
			struct in_addr ip;
			unsigned char netlen;

			net = strchr(linein + 4, '/');
			if (net) {
				unsigned int ui;

				*net++ = '\0';
				ui = strtoul(net, &net, 10);
				if ((*net != '\n') || (ui < 8) || (ui > 32))
					goto parse;
				netlen = (ui & 0xff);
			} else {
				*(strchr(linein + 4, '\n')) = '\0';
				netlen = 0;
			}
			if (!inet_pton(AF_INET, linein + 4, &ip))
				goto parse;

			newbuf  = realloc(editbuffer.buf.map.mem, editbuffer.buf.map.len + 5);
			if (!newbuf)
				goto nomem;
			editbuffer.buf.map.mem = newbuf;
			memcpy(newbuf + editbuffer.buf.map.len, &ip, 4);
			memcpy(newbuf + editbuffer.buf.map.len + 4, &netlen, 1);
			editbuffer.buf.map.len += 5;
		}
		break;
	case 4: {
			char *newbuf;
			char *net;
			struct in6_addr ip;
			unsigned char netlen;

			net = strchr(linein + 4, '/');
			if (net) {
				unsigned int ui;

				*net++ = '\0';
				ui = strtoul(net, &net, 10);
				if ((*net != '\n') || (ui < 8) || (ui > 128))
					goto parse;
				netlen = (ui & 0xff);
			} else {
				netlen = 0;
			}
			if (!inet_pton(AF_INET6, linein + 4, &ip))
				goto parse;

			newbuf  = realloc(editbuffer.buf.map.mem, editbuffer.buf.map.len + 17);
			if (!newbuf)
				goto nomem;
			editbuffer.buf.map.mem = newbuf;
			memcpy(newbuf + editbuffer.buf.map.len, &ip, 16);
			memcpy(newbuf + editbuffer.buf.map.len + 16, &netlen, 1);
			editbuffer.buf.map.len += 17;
		}
		break;
	}
	return;
nomem:
	oom();
	return;
parse:
	commstat = EINVAL;
	puts("ERROR: invalid argument");
}

static struct {
	const char *name;
	const unsigned int len;
	void (*func)(const int);
} edcmds[] = {
	{ .name = "write", .len = 5, .func = editwrite },
	{ .name = "add", .len = 3, .func = editadd },
	{ .name = "del", .len = 3, .func = NULL },
	{ .name = "show", .len = 4, .func = NULL },
	{ .name = "echo", .len = 4, .func = eecho },
	{ .name = "exit", .len = 4, .func = eXiT },
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
		{ .name = "spfignore", .len = 9, .type = 1 },
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
			/* errors are not caught */
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
			/* errors are not caught */
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
