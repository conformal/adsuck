# $adsuck$

PROG=adsuck
NOMAN=

SRCS= adsuck.c log.c
COPT+= -O2
DEBUG+= -ggdb3 
CFLAGS+= -Wall
CFLAGS+= -I/usr/local/include
LDFLAGS+= -L/usr/local/lib -lldns

.include <bsd.prog.mk>
