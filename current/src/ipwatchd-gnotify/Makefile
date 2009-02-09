# IPwatchD G Notify - Notification tool for Gnome environment
# Copyright (C) 2009 Jaroslav Imrich <jariq(at)jariq(dot)sk>

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
	mkdir -p /usr/local/bin
	cp ipwatchd-gnotify /usr/local/bin

uninstall:
	rm -f /usr/local/bin/ipwatchd-gnotify
