TARGETS=qsmtpd.o antispam.o auth.o starttls.o spf.o

.phony: all clean

vpath %.h ../include/

default: all

all:	$(TARGETS)

clean:
	rm -f *.o *~ \#* $(TARGETS)

qsmtpd.o: qsmtpd.h antispam.h log.h netio.h dns.h control.h tls.h sstring.h usercallback.h version.h vpopmail.h

auth.o: qsmtpd.h sstring.h netio.h base64.h log.h

starttls.o: tls.h netio.h control.h dns.h ssl_timeoutio.h qsmtpd.h

antispam.o: antispam.h dns.h log.h

spf.o: dns.h sstring.h antispam.h

vpopmail.o: vpopmail.h sstring.h

%.o: %.c
	 $(CC) $(CFLAGS) $<
