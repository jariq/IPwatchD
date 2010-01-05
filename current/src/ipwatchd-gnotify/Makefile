# IPwatchD G Notify - Notification tool for Gnome environment
# Copyright (C) 2009-2010 Jaroslav Imrich <jariq(at)jariq(dot)sk>

CC= gcc
CFLAGS= -Wall -O2
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
	cp ipwatchd-gnotify $(DESTDIR)/usr/sbin

uninstall:
	rm -f $(DESTDIR)/usr/sbin/ipwatchd-gnotify

