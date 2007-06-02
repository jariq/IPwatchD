CC= gcc
CFLAGS= -Wall -O2
LIBS= -lpcap -lnet


all: analyse.o config.o daemonize.o devinfo.o genarp.o ipwatchd.o message.o
	$(CC) $(CFLAGS) $(LIBS) analyse.o config.o daemonize.o devinfo.o genarp.o \
	  ipwatchd.o message.o -o ipwatchd

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


clean:
	-rm *.o

mrproper:
	-rm *.o ipwatchd
