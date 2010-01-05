# IPwatchD - IP conflict detection tool for Linux
# Copyright (C) 2007-2010 Jaroslav Imrich <jariq(at)jariq(dot)sk>

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
	-rm -f *.o

distclean: clean
	-rm -f ipwatchd


install:
	mkdir -p $(DESTDIR)/etc
	mkdir -p $(DESTDIR)/usr/sbin
	mkdir -p $(DESTDIR)/usr/share/man/man8
	cp ipwatchd $(DESTDIR)/usr/sbin
	cp scripts/ipwatchd-script $(DESTDIR)/usr/sbin
	cp scripts/ipwatchd $(DESTDIR)/etc/init.d
	cp ipwatchd.conf $(DESTDIR)/etc
	cp ../doc/ipwatchd.8.gz $(DESTDIR)/usr/share/man/man8

uninstall:
	rm -f $(DESTDIR)/usr/sbin/ipwatchd
	rm -f $(DESTDIR)/usr/sbin/ipwatchd-script
	rm -f $(DESTDIR)/etc/init.d/ipwatchd
	rm -f $(DESTDIR)/etc/ipwatchd.conf
	rm -f $(DESTDIR)/usr/share/man/man8/ipwatchd.8.gz

