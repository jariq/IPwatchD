IPwatchD
========

**IP conflict detection tool for Linux**

IPwatchD is a simple daemon that analyses all incoming ARP packets in order to detect IP conflicts on Linux. It can be configured to listen on one or more network interfaces in active or passive mode. In active mode it protects your host before IP takeover by answering Gratuitous ARP requests received from conflicting system. In passive mode it just records information about conflict through standard syslog interface.

Please visit project website - [ipwatchd.sourceforge.io](https://ipwatchd.sourceforge.io/) - for more information.

