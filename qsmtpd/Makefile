TARGETS=qsmtpd.o antispam.o auth.o starttls.o spf.o data.o addrsyntax.o

.phony: all clean

vpath %.h ../include/

default: all

all:	$(TARGETS)

clean:
	rm -f *.o *~ \#* $(TARGETS)

qsmtpd.o: qsmtpd.c qsmtpd.h antispam.h log.h netio.h dns.h control.h tls.h sstring.h userfilters.h version.h \
		vpop.h qsdata.h xtext.h
	$(CC) $(CFLAGS) -DAUTOQMAIL='"$(AUTOQMAIL)"' $<

auth.o: qsmtpd.h sstring.h netio.h base64.h log.h tls.h

starttls.o: tls.h netio.h control.h dns.h ssl_timeoutio.h qsmtpd.h

antispam.o: antispam.h libowfatconn.h log.h match.h netio.h

spf.o: libowfatconn.h sstring.h antispam.h match.h netio.h

vpop.o: vpop.h sstring.h cdb.h

data.o: netio.h log.h qsmtpd.h antispam.h version.h tls.h qsdata.h

addrsyntax.o: qsmtpd.h sstring.h dns.h

%.o: %.c
	$(CC) $(CFLAGS) $<
