OWFATPATH=../libowfat-0.20-eike
CDBPATH=../vpopmail-5.4.0/cdb
SHELL=/bin/sh
CC=gcc
CFLAGS=-O2 -c -Wall -W -I$(shell pwd)/include -DIPV4ONLY -g
LD=gcc
LDFLAGS= #-lefence
LDFLAGSSSL=-lssl -lcrypto
AUTOQMAIL=/var/qmail

export SHELL CC CFLAGS LD LDFLAGS AUTOQMAIL

SUBDIRS = lib callbacks qsmtpd qremote

TARGETS = targets/Qsmtpd targets/Qremote
TOOLS = targets/addipbl targets/testspf

.phony: all clean subdirs toolsub install normal

default: normal

all: subdirs toolsub $(TARGETS) $(TOOLS)

normal: subdirs $(TARGETS)

subdirs:
	for dir in $(SUBDIRS); do\
		$(MAKE) -C $$dir; \
	done

toolsub:
	$(MAKE) -C tools

vpath %.h ./include

clean:
	rm -f *.o *~ \#* $(TARGETS)
	for dir in $(SUBDIRS) tools; do\
		$(MAKE) -C $$dir clean; \
	done

targets/Qsmtpd: qsmtpd/qsmtpd.o qsmtpd/antispam.o qsmtpd/auth.o qsmtpd/starttls.o qsmtpd/spf.o \
		qsmtpd/vpopmail.o qsmtpd/data.o lib/log.o lib/netio.o lib/dns.o lib/control.o \
		lib/addrsyntax.o lib/getfile.o lib/ssl_timeoutio.o lib/tls.o lib/base64.o \
		lib/match.o \
		callbacks/badmailfrom.o callbacks/dnsbl.o callbacks/badcc.o callbacks/usersize.o \
		callbacks/rcpt_cbs.o callbacks/boolean.o callbacks/fromdomain.o \
		callbacks/check2822.o callbacks/ipbl.o callbacks/spf.o callbacks/soberg.o \
		callbacks/helo.o callbacks/forceesmtp.o \
		$(OWFATPATH)/libowfat.a $(CDBPATH)/cdb.a
	$(LD) $(LDFLAGS) $(LDFLAGSSSL) -o $@ $^

targets/Qremote: qremote/qremote.o lib/dns.o lib/netio.o lib/ssl_timeoutio.o lib/log.o lib/tls.o \
		lib/control.o lib/log.o lib/match.o $(OWFATPATH)/libowfat.a
	$(LD) $(LDFLAGS) $(LDFLAGSSSL) -o $@ $^

targets/addipbl: tools/addipbl.o
	$(LD) $(LDFLAGS) -o $@ $^

targets/testspf: tools/testspf.o qsmtpd/spf.o qsmtpd/antispam.o lib/dns.o lib/match.o \
		$(OWFATPATH)/libowfat.a
	$(LD) $(LDFLAGS) $(LDFLAGSSSL) -o $@ $^
	strip $@

install:
	install -s -g qmail -o qmaild targets/Qsmtpd $(AUTOQMAIL)/bin
#	install -s -g qmail -o qmailr targets/Qremote $(AUTOQMAIL)/bin
