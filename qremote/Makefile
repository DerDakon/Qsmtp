TARGETS=qremote.o

.phony: all clean

vpath %.h ../include/

default: all

all:	$(TARGETS)

clean:
	rm -f *.o *~ \#* $(TARGETS)

qremote.o: netio.h dns.h

%.o: %.c
	 $(CC) $(CFLAGS) $<
