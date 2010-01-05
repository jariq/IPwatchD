# IPwatchD X Notify - Notification tool for X window environment
# Copyright (C) 2009-2010 Jaroslav Imrich <jariq(at)jariq(dot)sk>

CC= gcc
CFLAGS= -Wall -O2
GTK_CFLAGS=`pkg-config --cflags gtk+-2.0`
GTK_LIBS=`pkg-config --libs gtk+-2.0`

all: ipwatchd-xnotify.c ipwatchd-xnotify.h
	$(CC) $(CFLAGS) $(GTK_CFLAGS) ipwatchd-xnotify.c -o ipwatchd-xnotify $(GTK_LIBS)

clean:
	-rm -f ipwatchd-xnotify

distclean:
	-rm -f ipwatchd-xnotify

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp ipwatchd-xnotify $(DESTDIR)/usr/bin

uninstall:
	rm -f $(DESTDIR)/usr/bin/ipwatchd-xnotify

