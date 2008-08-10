/* IPwatchD - IP conflict detection tool for Linux
 * Copyright (C) 2007 Jaroslav Imrich <jariq(at)jariq(dot)sk>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

/** \file devinfo.c
 * \brief Contains logic used for acquiring information about network devices
 */


#include "ipwatchd.h"


extern char msgbuf[IPWD_MSG_BUFSIZ];


//! Gets the IP and MAC addresses of specified device in human readable form
/*!
 * Based on examples from: http://english.geekpage.jp/programming/linux-network/
 * \param p_dev Name of the device (i.e. eth0)
 * \param p_ip Pointer to string where the IP address should be stored
 * \param p_mac Pointer to string where the MAC address should be stored
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_devinfo (char *p_dev, char *p_ip, char *p_mac)
{

	/* Create UDP socket */
	int sock = -1;
	sock = socket (AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Could not open socket");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy (ifr.ifr_name, p_dev);

	/* Get IP address of interface */
	if (ioctl (sock, SIOCGIFADDR, &ifr) < 0)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Could not retrieve IP address of the device \"%s\"", p_dev);
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	char *p_dev_ip = NULL;

	if ((p_dev_ip = inet_ntoa (((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr)) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Could not convert IP address of the device \"%s\"", p_dev);
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	strcpy (p_ip, p_dev_ip);

	/* Get MAC address of interface */
	if (ioctl (sock, SIOCGIFHWADDR, &ifr) < 0)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Could not retrieve IP address of the device \"%s\"", p_dev);
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	char *p_dev_mac = NULL;

	if ((p_dev_mac = ether_ntoa ((const struct ether_addr *) &ifr.ifr_hwaddr.sa_data[0])) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Could not convert IP address of the device \"%s\"", p_dev);
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	strcpy (p_mac, p_dev_mac);

	/* Close socket */
	close (sock);

	snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Device info: %s %s-%s", p_dev, p_ip, p_mac);
	ipwd_message (msgbuf, IPWD_MSG_DEBUG);

	return (IPWD_RV_SUCCESS);

}

