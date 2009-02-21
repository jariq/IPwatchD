/* IPwatchD - IP conflict detection tool for Linux
 * Copyright (C) 2007-2008 Jaroslav Imrich <jariq(at)jariq(dot)sk>
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

/** \file analyse.c
 * \brief Contains logic used for analysing of captured ARP packets
 */


#include "ipwatchd.h"


extern IPWD_S_DEVS devices;
extern char msgbuf[IPWD_MSG_BUFSIZ];
extern IPWD_S_CONFIG config;


//! Callback for "pcap_loop" with standard parameters. Called when ARP packet is received (detection of conflict is done here).
/*! 
 * \param args Last parameter of pcap_loop
 * \param header Packet header
 * \param packet Packet data
 */
void ipwd_analyse (u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
	struct timeval current_time;
	double difference = 0.0;
	char * command = NULL;
	int command_len = 0;
	int rv = 0;

	/* Get addresses from packet */
	IPWD_S_ARP_HEADER *arpaddr;
	arpaddr = (IPWD_S_ARP_HEADER *) (packet + IPWD_ARP_HEADER_SIZE);

	/* Source IP address */
	char rcv_sip[16];
	char *p_rcv_sip = NULL;

	if ((p_rcv_sip = inet_ntoa (*((struct in_addr *) &arpaddr->arp_spa))) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Could not get source IP address from packet");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return;
	}

	strcpy (rcv_sip, p_rcv_sip);

	/* Source MAC address */
	char rcv_smac[18];
	char *p_rcv_smac = NULL;

	if ((p_rcv_smac = ether_ntoa ((const struct ether_addr *) &arpaddr->arp_sha)) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Could not get source MAC address from packet");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return;
	}

	strcpy (rcv_smac, p_rcv_smac);

	/* Destination IP address */
	char rcv_dip[16];
	char *p_rcv_dip = NULL;

	if ((p_rcv_dip = inet_ntoa (*((struct in_addr *) &arpaddr->arp_tpa))) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Could not get destination IP address from packet");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return;
	}

	strcpy (rcv_dip, p_rcv_dip);

	/* Destination MAC address */
	char rcv_dmac[18];
	char *p_rcv_dmac = NULL;

	if ((p_rcv_dmac = ether_ntoa ((const struct ether_addr *) &arpaddr->arp_tha)) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Could not get destination MAC address from packet");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return;
	}

	strcpy (rcv_dmac, p_rcv_dmac);

	snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Received ARP packet: S:%s-%s D:%s-%s", rcv_sip, rcv_smac, rcv_dip, rcv_dmac);
	ipwd_message (msgbuf, IPWD_MSG_DEBUG);

	/* Search through devices structure */
	int i = 0;

	for (i = 0; i < devices.devnum; i++)
	{
		/* Get actual IP and MAC address of interface */
		if (ipwd_devinfo (devices.dev[i].device, devices.dev[i].ip, devices.dev[i].mac) == IPWD_RV_ERROR)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to get IP and MAC address of %s", devices.dev[i].device);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return;
		}

		/* Check if received packet causes conflict with IP address of this interface */
		if (!((strcmp (rcv_sip, devices.dev[i].ip) == 0) && (strcmp (rcv_smac, devices.dev[i].mac) != 0)))
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Packet does not conflict with: %s %s-%s", devices.dev[i].device, devices.dev[i].ip, devices.dev[i].mac);
			ipwd_message (msgbuf, IPWD_MSG_DEBUG);
			continue;
		}
	
		/* Get current system time */
		if (gettimeofday (&current_time, NULL) != 0)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to get current time");
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			continue;
		}

		difference = ((current_time.tv_sec + (current_time.tv_usec / 1000000.0)) - (devices.dev[i].time.tv_sec + (devices.dev[i].time.tv_usec / 1000000.0)));

		/* Check if current time is within the defend interval */
		if (difference < config.defend_interval)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "MAC address %s causes IP conflict with address %s set on interface %s - no action taken because this happened within the defend interval", rcv_smac, devices.dev[i].ip, devices.dev[i].device);
			ipwd_message (msgbuf, IPWD_MSG_ALERT);
		}	

		/* Handle IP conflict */
		if (devices.dev[i].mode == IPWD_MODE_ACTIVE)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "MAC address %s causes IP conflict with address %s set on interface %s - active mode - reply sent", rcv_smac, devices.dev[i].ip, devices.dev[i].device);
			ipwd_message (msgbuf, IPWD_MSG_ALERT);

			/* Send reply to conflicting system */
			ipwd_genarp (devices.dev[i].device, devices.dev[i].ip, devices.dev[i].mac, rcv_sip, rcv_smac, ARPOP_REPLY);

			/* Send GARP request to update cache of our neighbours */
			ipwd_genarp (devices.dev[i].device, devices.dev[i].ip, devices.dev[i].mac, devices.dev[i].ip, "ff:ff:ff:ff:ff:ff", ARPOP_REQUEST);
		}
		else
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "MAC address %s causes IP conflict with address %s set on interface %s - passive mode - reply not sent", rcv_smac, devices.dev[i].ip, devices.dev[i].device);
			ipwd_message (msgbuf, IPWD_MSG_ALERT);
		}

		if (config.script != NULL)
		{
			/* Run user-defined script in form: script "dev" "ip" "mac" */
			command_len = strlen (config.script) + 2 + strlen (devices.dev[i].device) + 3 + strlen (devices.dev[i].ip) + 3 + strlen (rcv_smac) + 2;

			if ((command = (char *) malloc (command_len * sizeof (char))) == NULL)
			{
				snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to execute user-defined script - malloc failed");
				ipwd_message (msgbuf, IPWD_MSG_ERROR);
				continue;
 			}

			snprintf (command, command_len, "%s \"%s\" \"%s\" \"%s\"", config.script, devices.dev[i].device, devices.dev[i].ip, rcv_smac);

			rv = system (command);
			if (rv == -1)
			{
				snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to execute user-defined script: %s", command);
				ipwd_message (msgbuf, IPWD_MSG_ERROR);
			}

			free (command);
			command = NULL;
		}
	}
}

