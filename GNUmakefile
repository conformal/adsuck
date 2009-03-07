# $adsuck$

CFLAGS+= -O2 -Wall -ggdb -D_GNU_SOURCE -D_BSD_SOURCE -I.
LDFLAGS+=

LDADD+= -lldns

CC= gcc

adsuck: adsuck.o log.o linux/strlcpy.o
	$(CC) $(LDFLAGS) -o $@ $+ $(LDADD)

clean:
	rm -f adsuck *.o linux/*.o
