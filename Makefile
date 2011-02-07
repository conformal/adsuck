# $adsuck$

PREFIX?=/usr/local
BINDIR=${PREFIX}/sbin
MANDIR= ${PREFIX}/man/cat

PROG=adsuck
MAN=adsuck.8

SRCS= adsuck.c log.c
COPT+= -O2
DEBUG+= -ggdb3 
CFLAGS+= -Wall
CFLAGS+= -I/usr/local/include
LDFLAGS+= -L/usr/local/lib -lldns -levent

.include <bsd.prog.mk>
