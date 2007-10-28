CC= gcc
CFLAGS= -Wall -O2
LIBS= -lpcap -lnet


all: analyse.o config.o daemonize.o devinfo.o genarp.o ipwatchd.o message.o signal.o
	$(CC) $(CFLAGS) analyse.o config.o daemonize.o devinfo.o genarp.o \
	ipwatchd.o message.o signal.o -o ipwatchd $(LIBS)

analyse.o: analyse.c ipwatchd.h
	$(CC) $(CFLAGS) -c analyse.c -o analyse.o

config.o: config.c ipwatchd.h
	$(CC) $(CFLAGS) -c config.c -o config.o

daemonize.o: daemonize.c ipwatchd.h
	$(CC) $(CFLAGS) -c daemonize.c -o daemonize.o

devinfo.o: devinfo.c ipwatchd.h
	$(CC) $(CFLAGS) -c devinfo.c -o devinfo.o

genarp.o: genarp.c ipwatchd.h
	$(CC) $(CFLAGS) -c genarp.c -o genarp.o

ipwatchd.o: ipwatchd.c ipwatchd.h
	$(CC) $(CFLAGS) -c ipwatchd.c -o ipwatchd.o
	
message.o: message.c ipwatchd.h
	$(CC) $(CFLAGS) -c message.c -o message.o

signal.o: signal.c ipwatchd.h
	$(CC) $(CFLAGS) -c signal.c -o signal.o


clean:
	-rm *.o

distclean:
	-rm *.o ipwatchd


install:
	cp ipwatchd /usr/local/sbin
	cp ipwatchd.conf /usr/local/etc

uninstall:
	rm /usr/local/sbin/ipwatchd
	rm /usr/local/etc/ipwatchd.conf

