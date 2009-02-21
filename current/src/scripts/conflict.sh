#!/bin/sh
#
# conflict.sh   Example of user-defined script
#
# Description:  This script can be called by IPwatchD daemon when IP conflict occures.

# Device
DEVICE=$1
# IP address
IP=$2
# MAC address of conflicting system
MAC=$3

# You can write own logic for any paritcular interface
case "$DEVICE" in

	eth0)
		# Just beep :)
		echo -e "\a"
		;;

	eth1)
		# Restart interface
		/sbin/ifdown eth1
		/sbin/ifup eth1
		;;

esac

# And run notification tool for X window environment in both cases
if [ -x /usr/local/bin/ipwatchd-xnotify ]; then
	/usr/local/bin/ipwatchd-xnotify \
		--broadcast \
		--title "IP conflict occured" \
		--message "MAC address $MAC causes IP conflict with address $IP set on interface $DEVICE"
fi

exit 0

