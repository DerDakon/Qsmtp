TARGETS = rcpt_cbs.o badmailfrom.o check2822.o dnsbl.o forcessl.o whitelistauth.o ipbl.o badcc.o fromdomain.o spf.o nobounce.o \
	  soberg.o

.phony: all clean

default: all

vpath %.h ../include/

all: $(TARGETS)

clean:
	rm -f $(TARGETS) *~ \#*

badmailfrom.o: control.h dns.h qsmtpd.h log.h

check2822.o: qsmtpd.h

dnsbl.o: antispam.h control.h dns.h log.h netio.h qsmtpd.h

forcessl.o: netio.h tls.h

ipbl.o: antispam.h control.h dns.h log.h netio.h qsmtpd.h

whitelistauth.o: qsmtpd.h

badcc.o: antispam.h control.h dns.h log.h netio.h qsmtpd.h

fromdomain.o: antispam.h control.h dns.h log.h netio.h qsmtpd.h

spf.o: antispam.h control.h dns.h log.h netio.h qsmtpd.h

nobounce.o:  netio.h qsmtpd.h

helo.o: control.h qsmtpd.h

soberg.o: netio.h qsmtpd.h

rcpt_cbs.o: log.h

%.o: %.c usercallback.h
	$(CC) $(CFLAGS) $<
