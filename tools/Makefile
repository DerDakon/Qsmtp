TARGETS=addipbl.o testspf.o fcshell.o clearpass.o qsurvey.o

.phony: all clean

vpath %.h ../include/

default: all

all:	$(TARGETS)

clean:
	rm -f *.o *~ \#* $(TARGETS)

testspf.o: qsmtpd.h antispam.h sstring.h

fcshell.o: fcshell.c
	$(CC) $(CFLAGS) --std=c99 $<

clearpass.o: sstring.h base64.h

qp.o: qoff.h

qsurvey.o: qsurvey.c starttlsr.h
	 $(CC) $(CFLAGS) -DAUTOQMAIL='"$(AUTOQMAIL)"' -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) $<
