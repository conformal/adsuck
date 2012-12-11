PREFIX?=/usr/local
BINDIR=${PREFIX}/sbin
MANDIR= ${PREFIX}/man/man

PROG=adsuck
MAN=adsuck.8

SRCS= adsuck.c log.c resolv.c
COPT+= -O2
DEBUG+= -g
CFLAGS+= -Wall
CFLAGS+= -I/usr/local/include
LDFLAGS+= -L/usr/local/lib -lldns -levent_extra -levent_core
BUILDVERSION != sh "${.CURDIR}/buildver.sh"
.if !${BUILDVERSION} == ""
CPPFLAGS+= -DADSUCK_BUILDSTR=\"$(BUILDVERSION)\"
.endif

beforeinstall:
	install -m 755 -d /var/adsuck/files
	install -m 644 ${.CURDIR}/files/hosts.small /var/adsuck/files
	install -m 644 ${.CURDIR}/files/hosts.yoyo /var/adsuck/files
	install -m 644 ${.CURDIR}/files/Hosts.blc /var/adsuck/files
	install -m 644 ${.CURDIR}/files/Hosts.mis /var/adsuck/files
	install -m 644 ${.CURDIR}/files/Hosts.pub /var/adsuck/files
	install -m 644 ${.CURDIR}/files/Hosts.rsk /var/adsuck/files
	install -m 644 ${.CURDIR}/files/Hosts.sex /var/adsuck/files
	install -m 644 ${.CURDIR}/files/Hosts.trc /var/adsuck/files

# clang targets
.if ${.TARGETS:M*analyze*}
CC=clang
CXX=clang++
CPP=clang -E
CFLAGS+=--analyze
.elif ${.TARGETS:M*clang*}
CC=clang
CXX=clang++
CPP=clang -E
.endif

analyze: all
clang: all

.include <bsd.prog.mk>
