# $adsuck$

PROG=adsuck
NOMAN=

COPT+= -O2
DEBUG+= -ggdb3 
CFLAGS+= -Wall
CFLAGS+= -I/usr/local/include
LDFLAGS+= -L/usr/local/lib -lldns

.include <bsd.prog.mk>
