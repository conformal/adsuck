PREFIX?= /usr/local
BINDIR?= $(PREFIX)/bin
MANDIR?= $(PREFIX)/share/man

CFLAGS+= -O2 -Wall -ggdb -D_GNU_SOURCE -D_BSD_SOURCE -I.
LDFLAGS+=

LDADD+= -lldns -levent

CC?= cc

adsuck: adsuck.o log.o linux/strlcpy.o resolv.o
	$(CC) $(LDFLAGS) -o $@ $+ $(LDADD)

clean:
	rm -f adsuck *.o linux/*.o

install: all
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 755 -d $(DESTDIR)$(MANDIR)/man1
	install -m 755 adsuck $(DESTDIR)$(BINDIR)
	install -m 644 adsuck.1 $(DESTDIR)$(MANDIR)/man1/adsuck.1
	install -m 755 -d /var/adsuck/files
	install -m 644 files/hosts.small /var/adsuck/files
	install -m 644 files/hosts.yoyo /var/adsuck/files
	install -m 644 files/Hosts.blc /var/adsuck/files
	install -m 644 files/Hosts.mis /var/adsuck/files
	install -m 644 files/Hosts.pub /var/adsuck/files
	install -m 644 files/Hosts.rsk /var/adsuck/files
	install -m 644 files/Hosts.sex /var/adsuck/files
	install -m 644 files/Hosts.trc /var/adsuck/files

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/adsuck
	rm -f $(DESTDIR)$(MANDIR)/man1/adsuck.1
	rm -f /var/adsuck/files/hosts.small
	rm -f /var/adsuck/files/hosts.yoyo
	rm -f /var/adsuck/files/Hosts.blc
	rm -f /var/adsuck/files/Hosts.mis
	rm -f /var/adsuck/files/Hosts.pub
	rm -f /var/adsuck/files/Hosts.rsk
	rm -f /var/adsuck/files/Hosts.sex
	rm -f /var/adsuck/files/Hosts.trc
	if [ -d /var/adsuck/files ]; then rmdir /var/adsuck/files; fi
	if [ -d /var/adsuck ]; then rmdir /var/adsuck; fi
