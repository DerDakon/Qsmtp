#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include "netio.h"
#include "dns.h"

int sd;

int
conn(const struct in6_addr remoteip, const int port)
{
	struct sockaddr_in6 sock;
	int rc;

	sd = socket(PF_INET6, SOCK_STREAM, 0);

	if (sd < 0)
		return errno;

	sock.sin6_family = AF_INET6;
	sock.sin6_port = 0;
//	sock.sin6_flowinfo = 0;
	sock.sin6_addr = in6addr_any;
//	sock.sin6_scope_id = 0;

	rc = bind(sd, &sock, sizeof(sock));

	if (rc)
		return errno;

	sock.sin6_port = htons(port);
	sock.sin6_addr = remoteip;

	rc = connect(sd, &sock, sizeof(sock));
	if (rc)
		return errno;

	return 0;
}

int
tryconn(const char *hostname)
{
	struct ips *mx, *thisip;
	int c;

	if (ask_dnsmx(hostname, &mx)) {
		//error message
		return 1;
	}

	thisip = mx;
	while (1) {
		int minpri = 65537;

		for (thisip = mx; thisip; thisip = thisip->next) {
			if (thisip->priority < minpri)
				minpri = thisip->priority;
		}
		if (minpri == 65537) {
			write(5, "can't connect\n", 14);
			return 1;
		}
		for (thisip = mx; thisip; thisip = thisip->next) {
			if (thisip->priority == minpri) {
				c = conn(thisip->addr, 25);
				if (c) {
					thisip->priority = 65537;
				} else {
					return 0;
				}
			}
		}
	}
}

int
main(int argc, char *argv[])
{
	char *foo[4];
	int i;

	if (argc < 5) {
		write(2, "too few arguments\n", 18);
		return 0;
	}

	if (tryconn(argv[1]))
		return 0;

	dup2(1,5);
	dup2(sd,1);
	dup2(sd,0);

	net_read();
	write(5, linein, linelen);write(5,"\n",1);
	netwrite("ehlo Qremote\r\n");
	do {
		net_read();
		write(5, linein, linelen);write(5,"\n",1);
	} while (linein[3] == '-');
	foo[0] = "MAIL FROM:<";
	foo[1] = argv[3];
	foo[2] = ">";
	foo[3] = NULL;
	net_writen(foo);
	net_read();
	write(5, linein, linelen);write(5,"\n",1);
	foo[0] = "RCPT TO:<";
	for (i = 4; i < argc; i++) {
		foo[1] = argv[i];
		net_writen(foo);
		net_read();
		write(5, linein, linelen);write(5,"\n",1);
	}
	netwrite("DATA\r\n");
	net_read();
	write(5, linein, linelen);write(5,"\n",1);
	netwrite("Subject: test qremote\r\n\r\n.\r\n");
	net_read();
	write(5, linein, linelen);write(5,"\n",1);
	netwrite("QUIT\r\n");
	net_read();
	write(5, linein, linelen);write(5,"\n",1);
	
	close(sd);

	return 0;
}
