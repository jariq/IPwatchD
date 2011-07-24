# IPwatchD - IP conflict detection tool for Linux
# Copyright (C) 2007-2010 Jaroslav Imrich <jariq(at)jariq(dot)sk>

CC= gcc
CFLAGS= -g -Wall -O2
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

distclean: clean
	-rm ipwatchd


install:
	mkdir -p $(DESTDIR)/etc/init.d
	mkdir -p $(DESTDIR)/usr/sbin
	mkdir -p $(DESTDIR)/usr/share/man/man8
	mkdir -p $(DESTDIR)/usr/share/man/man5
	mkdir -p $(DESTDIR)/usr/share/man/man1
	cp ipwatchd $(DESTDIR)/usr/sbin
	cp scripts/ipwatchd-script $(DESTDIR)/usr/sbin
	cp scripts/ipwatchd $(DESTDIR)/etc/init.d
	cp ipwatchd.conf $(DESTDIR)/etc
	cp ../doc/ipwatchd.8.gz $(DESTDIR)/usr/share/man/man8
	cp ../doc/ipwatchd.conf.5.gz $(DESTDIR)/usr/share/man/man5
	cp ../doc/ipwatchd-script.1.gz $(DESTDIR)/usr/share/man/man1

uninstall:
	rm $(DESTDIR)/usr/sbin/ipwatchd
	rm $(DESTDIR)/usr/sbin/ipwatchd-script
	rm $(DESTDIR)/etc/init.d/ipwatchd
	rm $(DESTDIR)/etc/ipwatchd.conf
	rm $(DESTDIR)/usr/share/man/man8/ipwatchd.8.gz
	rm $(DESTDIR)/usr/share/man/man5/ipwatchd.conf.5.gz
	rm $(DESTDIR)/usr/share/man/man1/ipwatchd-script.1.gz

