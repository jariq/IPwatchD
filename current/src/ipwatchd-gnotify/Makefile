# IPwatchD G Notify - Notification tool for Gnome environment
# Copyright (C) 2009-2010 Jaroslav Imrich <jariq(at)jariq(dot)sk>

CC= gcc
CFLAGS= -g -Wall -O2
LIBNOTIFY_CFLAGS=`pkg-config --cflags libnotify`
LIBNOTIFY_LIBS=`pkg-config --libs libnotify`

all: ipwatchd-gnotify.c ipwatchd-gnotify.h
	$(CC) $(CFLAGS) $(LIBNOTIFY_CFLAGS) ipwatchd-gnotify.c -o ipwatchd-gnotify $(LIBNOTIFY_LIBS)

clean:
	-rm -f ipwatchd-gnotify

distclean:
	-rm -f ipwatchd-gnotify

install:
	mkdir -p $(DESTDIR)/usr/sbin
	mkdir -p $(DESTDIR)/usr/share/man/man1
	cp ipwatchd-gnotify $(DESTDIR)/usr/sbin
	cp ../../doc/ipwatchd-gnotify.1.gz $(DESTDIR)/usr/share/man/man1

uninstall:
	rm -f $(DESTDIR)/usr/sbin/ipwatchd-gnotify
	rm $(DESTDIR)/usr/share/man/man1/ipwatchd-gnotify.1.gz
