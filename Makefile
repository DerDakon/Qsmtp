OWFATPATH=/mnt/misc/qmail/libowfat-0.20-eike
CDBPATH=/mnt/misc/qmail/vpopmail-5.4.0/cdb
SHELL=/bin/sh
CC=gcc
CFLAGS=-O2 -c -Wall -W -I$(shell pwd)/include -DIPV4ONLY -DAUTHCRAM -s #-g
LD=gcc
LDFLAGS=-lssl -lcrypto #-lefence

export SHELL CC CFLAGS LD LDFLAGS

SUBDIRS = lib callbacks qsmtpd

TARGETS = targets/Qsmtpd targets/addipbl

.phony: all clean subdirs

default: all

all: subdirs $(TARGETS)

subdirs:
	for dir in $(SUBDIRS); do\
		$(MAKE) -C $$dir; \
	done

vpath %.h ./include

clean:
	rm -f *.o *~ \#* $(TARGETS)
	for dir in $(SUBDIRS); do\
		$(MAKE) -C $$dir clean; \
	done

targets/Qsmtpd: qsmtpd/qsmtpd.o qsmtpd/antispam.o qsmtpd/auth.o qsmtpd/starttls.o qsmtpd/spf.o \
		qsmtpd/vpopmail.o lib/log.o lib/netio.o lib/dns.o lib/control.o lib/addrsyntax.o \
		lib/getfile.o lib/ssl_timeoutio.o lib/tls.o lib/base64.o \
		callbacks/badmailfrom.o callbacks/dnsbl.o callbacks/badcc.o \
		callbacks/rcpt_cbs.o callbacks/forcessl.o callbacks/fromdomain.o \
		callbacks/whitelistauth.o callbacks/check2822.o callbacks/ipbl.o \
		callbacks/spf.o callbacks/nobounce.o callbacks/soberg.o callbacks/helo.o \
		$(OWFATPATH)/libowfat.a $(CDBPATH)/cdb.a
	$(LD) $(LDFLAGS) -o $@ $^
	#chown qmaild:qmail $@

targets/addipbl: targets/addipbl.o
	$(LD) $(LDFLAGS) -o $@ $^

targets/addipbl.o: targets/addipbl.c
