TARGETS = rcpt_cbs.o badmailfrom.o check2822.o dnsbl.o ipbl.o badcc.o fromdomain.o spf.o boolean.o soberg.o \
	  helo.o usersize.o forceesmtp.o

.phony: all clean

default: all

vpath %.h ../include/

all: $(TARGETS)

clean:
	rm -f $(TARGETS) *~ \#*

badmailfrom.o: control.h dns.h qsmtpd.h log.h

check2822.o: qsmtpd.h

dnsbl.o: antispam.h control.h dns.h log.h netio.h qsmtpd.h

boolean.o: qsmtpd.h tls.h netio.h log.h

ipbl.o: antispam.h control.h dns.h log.h netio.h qsmtpd.h

badcc.o: antispam.h control.h dns.h log.h netio.h qsmtpd.h

fromdomain.o: antispam.h control.h dns.h log.h netio.h qsmtpd.h

spf.o: antispam.h control.h dns.h log.h netio.h qsmtpd.h

helo.o: control.h qsmtpd.h

soberg.o: netio.h qsmtpd.h

usersize.o: netio.h qsmtpd.h

rcpt_cbs.o: log.h

forceesmtp.o: antispam.h control.h dns.h log.h qsmtpd.h

%.o: %.c usercallback.h
	$(CC) $(CFLAGS) $<
