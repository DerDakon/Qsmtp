TARGETS = netio.o dns.o log.o control.o ssl_timeoutio.o tls.o getfile.o base64.o match.o

.phony: all clean

default: all

all: $(TARGETS)

vpath %.h ../include

clean:
	rm -f $(TARGETS) *.o *~ \#*

base64.o: sstring.h

control.o: log.h dns.h

getfile.o: usercallback.h control.h

netio.o: log.h ssl_timeoutio.h tls.h

ssl_timeoutio.o: log.h tls.h

%.o: %.c %.h
	$(CC) $(CFLAGS) $<
