# IPwatchD - IP conflict detection tool for Linux
# Copyright (C) 2007-2008 Jaroslav Imrich <jariq(at)jariq(dot)sk>

CC= gcc
CFLAGS= -Wall -O2
LIBS= -lpcap -lnet
LIBNOTIFY_CFLAGS=`pkg-config --cflags libnotify`
LIBNOTIFY_LIBS=`pkg-config --libs libnotify`


all: analyse-wdn.o config.o daemonize.o desktop.o devinfo.o genarp.o ipwatchd.o ipwd-notify.o message.o signal.o
	$(CC) $(CFLAGS) analyse-wdn.o config.o daemonize.o desktop.o devinfo.o genarp.o \
	ipwatchd.o message.o signal.o -o ipwatchd $(LIBS)
	$(CC) $(CFLAGS) ipwd-notify.o -o ipwd-notify $(LIBNOTIFY_LIBS)

daemon: analyse.o config.o daemonize.o devinfo.o genarp.o ipwatchd.o message.o signal.o
	$(CC) $(CFLAGS) analyse.o config.o daemonize.o devinfo.o genarp.o \
	ipwatchd.o message.o signal.o -o ipwatchd $(LIBS)


analyse.o: analyse.c ipwatchd.h
	$(CC) $(CFLAGS) -c analyse.c -o analyse.o

analyse-wdn.o: analyse.c ipwatchd.h
	$(CC) $(CFLAGS) -DWITH_DESKTOP_NOTIFICATION -c analyse.c -o analyse-wdn.o

config.o: config.c ipwatchd.h
	$(CC) $(CFLAGS) -c config.c -o config.o

daemonize.o: daemonize.c ipwatchd.h
	$(CC) $(CFLAGS) -c daemonize.c -o daemonize.o

desktop.o: desktop.c ipwatchd.h
	$(CC) $(CFLAGS) -c desktop.c -o desktop.o

devinfo.o: devinfo.c ipwatchd.h
	$(CC) $(CFLAGS) -c devinfo.c -o devinfo.o

genarp.o: genarp.c ipwatchd.h
	$(CC) $(CFLAGS) -c genarp.c -o genarp.o

ipwatchd.o: ipwatchd.c ipwatchd.h
	$(CC) $(CFLAGS) -c ipwatchd.c -o ipwatchd.o

ipwd-notify.o: ipwd-notify.c
	$(CC) $(CFLAGS) $(LIBNOTIFY_CFLAGS) -c ipwd-notify.c -o ipwd-notify.o
	
message.o: message.c ipwatchd.h
	$(CC) $(CFLAGS) -c message.c -o message.o

signal.o: signal.c ipwatchd.h
	$(CC) $(CFLAGS) -c signal.c -o signal.o


clean:
	-rm -f *.o

distclean:
	-rm -f *.o ipwatchd ipwd-notify


install:
	mkdir -p /usr/local/etc
	mkdir -p /usr/local/sbin
	mkdir -p /usr/local/share/man/man8
	cp ipwatchd /usr/local/sbin
	-cp ipwd-notify /usr/local/sbin
	cp ipwatchd.conf /usr/local/etc
	cp ../doc/ipwatchd.8.gz /usr/local/share/man/man8

uninstall:
	rm -f /usr/local/sbin/ipwatchd
	-rm -f /usr/local/sbin/ipwd-notify
	rm -f /usr/local/etc/ipwatchd.conf
	rm -f /usr/local/share/man/man8/ipwatchd.8.gz

