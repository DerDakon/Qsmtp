TARGETS=addipbl.o testspf.o fcshell.o

.phony: all clean

vpath %.h ../include/

default: all

all:	$(TARGETS)

clean:
	rm -f *.o *~ \#* $(TARGETS)

testspf.o: qsmtpd.h antispam.h sstring.h

%.o: %.c
	$(CC) $(CFLAGS) $<
