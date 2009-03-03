adsuck: adsuck.c
	cc -ggdb3 -Wall -O2 -I /usr/local/include/ adsuck.c -L /usr/local/lib -lldns -o adsuck
clean:
	rm adsuck
