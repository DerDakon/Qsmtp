TARGETS = rcptfilters.a

OBJS = rcpt_filters.o badmailfrom.o check2822.o dnsbl.o ipbl.o badcc.o fromdomain.o spf.o boolean.o soberg.o \
	  helo.o usersize.o forceesmtp.o namebl.o

.phony: all clean

default: all

vpath %.h ../include/

all: $(OBJS) $(TARGETS)

clean:
	rm -f $(TARGETS) $(OBJS) *~ \#*

badmailfrom.o: control.h qsmtpd.h log.h

check2822.o: qsmtpd.h

dnsbl.o: antispam.h control.h log.h netio.h qsmtpd.h

boolean.o: qsmtpd.h tls.h netio.h log.h

ipbl.o: antispam.h log.h qsmtpd.h

badcc.o: control.h qsmtpd.h

fromdomain.o: antispam.h control.h log.h netio.h qsmtpd.h match.h

spf.o: antispam.h control.h log.h netio.h qsmtpd.h

helo.o: control.h qsmtpd.h

soberg.o: netio.h qsmtpd.h

usersize.o: netio.h qsmtpd.h

rcpt_filters.o: log.h

forceesmtp.o: antispam.h control.h qsmtpd.h

namebl.o: antispam.h control.h dns.h log.h netio.h qsmtpd.h

%.o: %.c usercallback.h
	$(CC) $(CFLAGS) $<

rcptfilters.a: rcptfilters.a($(OBJS))
