/* IPwatchD - IP conflict detection tool for Linux
 * Copyright (C) 2007-2010 Jaroslav Imrich <jariq(at)jariq(dot)sk>
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


extern IPWD_S_CONFIG config;
extern IPWD_S_DEVS devices;


//! Gets the IP and MAC addresses of specified device in human readable form
/*!
 * Based on examples from: http://english.geekpage.jp/programming/linux-network/
 * \param p_dev Name of the device (i.e. eth0)
 * \param p_ip Pointer to string where the IP address should be stored
 * \param p_mac Pointer to string where the MAC address should be stored
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_devinfo (const char *p_dev, char *p_ip, char *p_mac)
{

	/* Create UDP socket */
	int sock = -1;
	sock = socket (AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		ipwd_message (IPWD_MSG_ERROR, "Could not open socket");
		return (IPWD_RV_ERROR);
	}

	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy (ifr.ifr_name, p_dev);

	/* Get IP address of interface */
	if (ioctl (sock, SIOCGIFADDR, &ifr) < 0)
	{
		ipwd_message (IPWD_MSG_ERROR, "Could not retrieve IP address of the device \"%s\"", p_dev);
		return (IPWD_RV_ERROR);
	}

	char *p_dev_ip = NULL;

	/* Following variable was added because gcc 4.4.1 displayed warning: dereferencing pointer ‘({anonymous})’ does break strict-aliasing rules */
	struct in_addr sin_addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

	if ((p_dev_ip = inet_ntoa (sin_addr)) == NULL)
	{
		ipwd_message (IPWD_MSG_ERROR, "Could not convert IP address of the device \"%s\"", p_dev);
		return (IPWD_RV_ERROR);
	}

	strcpy (p_ip, p_dev_ip);

	/* Get MAC address of interface */
	if (ioctl (sock, SIOCGIFHWADDR, &ifr) < 0)
	{
		ipwd_message (IPWD_MSG_ERROR, "Could not retrieve IP address of the device \"%s\"", p_dev);
		return (IPWD_RV_ERROR);
	}

	char *p_dev_mac = NULL;

	if ((p_dev_mac = ether_ntoa ((const struct ether_addr *) &ifr.ifr_hwaddr.sa_data[0])) == NULL)
	{
		ipwd_message (IPWD_MSG_ERROR, "Could not convert IP address of the device \"%s\"", p_dev);
		return (IPWD_RV_ERROR);
	}

	strcpy (p_mac, p_dev_mac);

	/* Close socket */
	close (sock);

	ipwd_message (IPWD_MSG_DEBUG, "Device info: %s %s-%s", p_dev, p_ip, p_mac);

	return (IPWD_RV_SUCCESS);

}


//! Gets list of available network interfaces and fills devices structure with acquired information
/*!
 * Based on example from: http://www.doctort.org/adam/nerd-notes/enumerating-network-interfaces-on-linux.html
 * See netdevice(7) manual page for more information.
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_fill_devices (void)
{

	int sock = -1;

	char ifaces_buf[10240];
	struct ifconf ifc;
	struct ifreq * ifr = NULL;
	struct ifreq * iface = NULL;

	int ifaces_num = 0;
	int i = 0;

    pcap_t *h_pcap = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

	memset (ifaces_buf, 0, sizeof (ifaces_buf));
	memset (&ifc, 0, sizeof (ifc));
	memset (errbuf, 0, PCAP_ERRBUF_SIZE);

	/* Verify that devices structure is empty and configuration mode is automatic */
	if ((devices.dev != NULL) || (devices.devnum != 0) || (config.mode != IPWD_MODE_AUTOMATIC))
	{
		ipwd_message (IPWD_MSG_ERROR, "Cannot proceed with automatic configuration. Please check that configuration file does not contain iface variables");
		return (IPWD_RV_ERROR);
	}

	/* Create UDP socket */
	sock = socket (AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		ipwd_message (IPWD_MSG_ERROR, "Could not open socket");
		return (IPWD_RV_ERROR);
	}

	/* Set buffer */
	ifc.ifc_len = sizeof (ifaces_buf);
	ifc.ifc_buf = ifaces_buf;

	/* Get list of interfaces */
	if (ioctl (sock, SIOCGIFCONF, &ifc) < 0)
	{
		ipwd_message (IPWD_MSG_ERROR, "Could not retrieve list of network interfaces");
		return (IPWD_RV_ERROR);
	}

	/* Determine number of interfaces */
	ifaces_num = ifc.ifc_len / sizeof (struct ifreq);

	/* Get pointer to array with interfaces */
	ifr = ifc.ifc_req;

	/* Loop through array with interfaces */
	for (i = 0; i < ifaces_num; i++)
	{
		iface = &ifr[i];

		/* Check if device is valid ethernet device */
		h_pcap = pcap_open_live (iface->ifr_name, BUFSIZ, 0, 0, errbuf);
		if (h_pcap == NULL)
		{
			ipwd_message (IPWD_MSG_ERROR, "IPwatchD is unable to work with device \"%s\"", iface->ifr_name);
			return (IPWD_RV_ERROR);
		}

		if (pcap_datalink (h_pcap) != DLT_EN10MB)
		{
			ipwd_message (IPWD_MSG_ERROR, "Device \"%s\" is not valid ethernet device", iface->ifr_name);
			return (IPWD_RV_ERROR);
		}

		pcap_close (h_pcap);

		/* Put read values into devices structure */
		if ((devices.dev = (IPWD_S_DEV *) realloc (devices.dev, (devices.devnum + 1) * sizeof (IPWD_S_DEV))) == NULL)
		{
			ipwd_message (IPWD_MSG_ERROR, "Unable to resize devices structure");
			return (IPWD_RV_ERROR);
		}

		strncpy (devices.dev[devices.devnum].device, iface->ifr_name, 9);
		*(devices.dev[devices.devnum].device + 9) = '\0';
		devices.dev[devices.devnum].mode = IPWD_MODE_PASSIVE;

		/* Set time of last conflict */
		devices.dev[devices.devnum].time.tv_sec = 0;
		devices.dev[devices.devnum].time.tv_usec = 0;

		ipwd_message (IPWD_MSG_DEBUG, "Found device %s", devices.dev[devices.devnum].device);

		devices.devnum = devices.devnum + 1;

	}

	/* Close socket */
	close (sock);

	return (IPWD_RV_SUCCESS);

}

