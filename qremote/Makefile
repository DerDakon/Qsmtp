TARGETS=qremote.o

.phony: all clean

vpath %.h ../include/

default: all

all:	$(TARGETS)

clean:
	rm -f *.o *~ \#* $(TARGETS)

qremote.o: qremote.c netio.h dns.h control.h log.h
	 $(CC) $(CFLAGS) -DAUTOQMAIL='"$(AUTOQMAIL)"' -o $@ $<

%.o: %.c
#	 $(CC) $(CFLAGS) $<
