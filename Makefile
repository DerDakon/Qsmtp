OWFATPATH=../../libowfat-0.22
CDBPATH=../../qmail-1.03
SHELL=/bin/sh
CC=gcc
CFLAGS=-O2 -c -Wall -W -Wshadow -I$(shell pwd)/include -DNOSTDERR -DUSESYSLOG -march=i686 -g
LD=gcc
LDFLAGS= #-lefence
LDFLAGSSSL=-lssl -lcrypto
AUTOQMAIL=/var/qmail

export SHELL CC CFLAGS LD LDFLAGS AUTOQMAIL

SUBDIRS = lib qsmtpd qsmtpd/filters qremote

TARGETS = targets/Qsmtpd targets/Qremote
TOOLS = targets/addipbl targets/testspf targets/fcshell

.PHONY: all clean toolsub install targets tools $(SUBDIRS)
.SECONDARY:

default: targets

all: targets tools

targets: $(SUBDIRS) $(TARGETS)

$(SUBDIRS):
	$(MAKE) -C $@

tools: toolsub $(TOOLS)

toolsub:
	$(MAKE) -C tools

vpath %.h ./include

clean:
	rm -f *.o *~ \#* $(TARGETS) $(TOOLS)
	for dir in $(SUBDIRS) tools; do \
		$(MAKE) -C $$dir clean; \
	done

targets/Qsmtpd: qsmtpd/qsmtpd.o qsmtpd/antispam.o qsmtpd/auth.o qsmtpd/starttls.o qsmtpd/spf.o \
		qsmtpd/vpopmail.o qsmtpd/data.o qsmtpd/addrsyntax.o qsmtpd/filters/rcptfilters.a \
		lib/dns.o lib/control.o lib/getfile.o lib/ssl_timeoutio.o lib/tls.o lib/base64.o \
		lib/match.o lib/log.o lib/netio.o \
		$(OWFATPATH)/libowfat.a $(CDBPATH)/cdb.a
	$(LD) $(LDFLAGS) $(LDFLAGSSSL) -o $@ $^

targets/Qremote: qremote/qremote.o qremote/conn.o qremote/starttlsr.o qremote/qrdata.o lib/dns.o \
		lib/netio.o lib/ssl_timeoutio.o lib/log.o lib/tls.o lib/control.o lib/log.o \
		lib/match.o lib/ssl_timeoutio.o lib/tls.o lib/mime.o $(OWFATPATH)/libowfat.a
	$(LD) $(LDFLAGS) $(LDFLAGSSSL) -o $@ $^

targets/testspf: tools/testspf.o qsmtpd/spf.o qsmtpd/antispam.o lib/dns.o lib/match.o \
		lib/netio.o lib/tls.o lib/ssl_timeoutio.o $(OWFATPATH)/libowfat.a
	$(LD) $(LDFLAGS) $(LDFLAGSSSL) -o $@ $^
	strip $@

lib/%.o qsmtpd/filters/%.o qsmtpd/%.o qremote/%.o tools/%.o:
	$(MAKE) -C $(@D) $(@F)

targets/%: tools/%.o
	$(LD) $(LDFLAGS) -o $@ $^

install:
	install -s -g qmail -o qmaild targets/Qsmtpd $(AUTOQMAIL)/bin
	install -s -g qmail -o qmailr targets/Qremote $(AUTOQMAIL)/bin
