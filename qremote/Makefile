TARGETS=qremote.o conn.o starttlsr.o

.phony: all clean

vpath %.h ../include/

default: all

all:	$(TARGETS)

clean:
	rm -f *.o *~ \#* $(TARGETS)

qremote.o: qremote.c netio.h dns.h control.h log.h sstring.h conn.h starttlsr.h
	 $(CC) $(CFLAGS) -DAUTOQMAIL='"$(AUTOQMAIL)"' -o $@ $<

conn.o: conn.h dns.h control.h log.h match.h

starttlsr.o: tls.h ssl_timeoutio.h qremote.h control.h netio.h sstring.h starttlsr.h

%.o: %.c
	 $(CC) $(CFLAGS) $<
