TARGETS=qsmtpd.o antispam.o auth.o starttls.o spf.o data.o

.phony: all clean

vpath %.h ../include/

default: all

all:	$(TARGETS)

clean:
	rm -f *.o *~ \#* $(TARGETS)

qsmtpd.o: qsmtpd.c qsmtpd.h antispam.h log.h netio.h dns.h control.h tls.h sstring.h usercallback.h version.h vpopmail.h
	$(CC) $(CFLAGS) -DAUTOQMAIL='"$(AUTOQMAIL)"' $<

auth.o: qsmtpd.h sstring.h netio.h base64.h log.h tls.h

starttls.o: tls.h netio.h control.h dns.h ssl_timeoutio.h qsmtpd.h

antispam.o: antispam.h dns.h log.h match.h netio.h

spf.o: dns.h sstring.h antispam.h match.h netio.h

vpopmail.o: vpopmail.h sstring.h

data.o: netio.h log.h qsmtpd.h antispam.h version.h tls.h

addrsyntax.o: qsmtpd.h sstring.h dns.h

%.o: %.c
	$(CC) $(CFLAGS) $<
