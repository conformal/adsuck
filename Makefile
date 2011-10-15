PREFIX?=/usr/local
BINDIR=${PREFIX}/sbin
MANDIR= ${PREFIX}/man/man

PROG=adsuck
MAN=adsuck.8

SRCS= adsuck.c log.c
COPT+= -O2
DEBUG+= -ggdb3 
CFLAGS+= -Wall
CFLAGS+= -I/usr/local/include
LDFLAGS+= -L/usr/local/lib -lldns -levent
BUILDVERSION != sh "${.CURDIR}/buildver.sh"
.if !${BUILDVERSION} == ""
CPPFLAGS+= -DADSUCK_BUILDSTR=\"$(BUILDVERSION)\"
.endif

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
