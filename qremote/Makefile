TARGETS=qremote.o conn.o

.phony: all clean

vpath %.h ../include/

default: all

all:	$(TARGETS)

clean:
	rm -f *.o *~ \#* $(TARGETS)

qremote.o: qremote.c netio.h dns.h control.h log.h sstring.h conn.h
	 $(CC) $(CFLAGS) -DAUTOQMAIL='"$(AUTOQMAIL)"' -o $@ $<

conn.o: conn.h dns.h control.h log.h match.h

%.o: %.c
	 $(CC) $(CFLAGS) $<
