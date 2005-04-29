TARGETS=qremote.o conn.o starttlsr.o qrdata.o

.phony: all clean

vpath %.h ../include/

default: all

all:	$(TARGETS)

clean:
	rm -f *.o *~ \#* $(TARGETS)

qremote.o: qremote.c netio.h dns.h control.h log.h sstring.h conn.h starttlsr.h qrdata.h
	 $(CC) $(CFLAGS) -DAUTOQMAIL='"$(AUTOQMAIL)"' -o $@ $<

conn.o: conn.h dns.h control.h log.h match.h

starttlsr.o: tls.h ssl_timeoutio.h qremote.h control.h netio.h sstring.h starttlsr.h

qrdata.o: netio.h qrdata.h qremote.h version.h mime.h

%.o: %.c
	 $(CC) $(CFLAGS) $<
