TARGETS=addipbl.o

.phony: all clean

vpath %.h ../include/

default: all

all:	$(TARGETS)

clean:
	rm -f *.o *~ \#* $(TARGETS)

%.o: %.c
	 $(CC) $(CFLAGS) $<
