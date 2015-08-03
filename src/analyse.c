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

/** \file analyse.c
 * \brief Contains logic used for analysing of captured ARP packets
 */


#include "ipwatchd.h"


extern IPWD_S_DEVS devices;
extern IPWD_S_CONFIG config;
extern int testing_flag;


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
	int i = 0;

	/* Get addresses from packet */
	IPWD_S_ARP_HEADER *arpaddr;
	arpaddr = (IPWD_S_ARP_HEADER *) (packet + IPWD_ARP_HEADER_SIZE);

	/* Source IP address */
	char rcv_sip[IPWD_MAX_DEVICE_ADDRESS_LEN];
	char *p_rcv_sip = NULL;

	/* Following variable was added because gcc 4.4.1 displayed warning: dereferencing type-punned pointer will break strict-aliasing rules */
	struct in_addr * p_arp_spa = (struct in_addr *) &arpaddr->arp_spa;

	if ((p_rcv_sip = inet_ntoa (*(p_arp_spa))) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not get source IP address from packet");
		return;
	}

	memset (rcv_sip, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
	strncpy (rcv_sip, p_rcv_sip, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);

	/* Source MAC address */
	char rcv_smac[IPWD_MAX_DEVICE_ADDRESS_LEN];
	char *p_rcv_smac = NULL;

	if ((p_rcv_smac = ether_ntoa ((const struct ether_addr *) &arpaddr->arp_sha)) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not get source MAC address from packet");
		return;
	}

	memset (rcv_smac, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
	strncpy (rcv_smac, p_rcv_smac, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);

	/* Destination IP address */
	char rcv_dip[IPWD_MAX_DEVICE_ADDRESS_LEN];
	char *p_rcv_dip = NULL;

	/* Following variable was added because gcc 4.4.1 displayed warning: dereferencing type-punned pointer will break strict-aliasing rules */
	struct in_addr * p_arp_tpa = (struct in_addr *) &arpaddr->arp_tpa;

	if ((p_rcv_dip = inet_ntoa (*(p_arp_tpa))) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not get destination IP address from packet");
		return;
	}

	memset (rcv_dip, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
	strncpy (rcv_dip, p_rcv_dip, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);

	/* Destination MAC address */
	char rcv_dmac[IPWD_MAX_DEVICE_ADDRESS_LEN];
	char *p_rcv_dmac = NULL;

	if ((p_rcv_dmac = ether_ntoa ((const struct ether_addr *) &arpaddr->arp_tha)) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not get destination MAC address from packet");
		return;
	}

	memset (rcv_dmac, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
	strncpy (rcv_dmac, p_rcv_dmac, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);

	ipwd_message (IPWD_MSG_TYPE_DEBUG, "Received ARP packet: S:%s-%s D:%s-%s", rcv_sip, rcv_smac, rcv_dip, rcv_dmac);

	/* Update devices structure with actual IP and MAC addresses of interfaces */
	for (i = 0; i < devices.devnum; i++)
	{
		if (ipwd_devinfo (devices.dev[i].device, devices.dev[i].ip, devices.dev[i].mac) == IPWD_RV_ERROR)
		{
			devices.dev[i].state = IPWD_DEVICE_STATE_UNUSABLE;
			continue;
		}
		else
		{
			devices.dev[i].state = IPWD_DEVICE_STATE_USABLE;
		}

		/* Ignore packets coming from local interfaces */
		if (strcasecmp (rcv_smac, devices.dev[i].mac) == 0)
		{
			if (strcasecmp (rcv_sip, devices.dev[i].ip) == 0)
			{
				ipwd_message (IPWD_MSG_TYPE_DEBUG, "ARP packet ignored because it comes from local interface.");
			}
			else
			{
				/* Happens when there is more than one interface connected to the same subnet */
				ipwd_message (IPWD_MSG_TYPE_DEBUG, "ARP packet ignored because it comes from local machine.");
			}

			return;
		}
	}

	/* Search through devices structure */
	for (i = 0; i < devices.devnum; i++)
	{
		/* Skip devices that are currently unusable */
		if (devices.dev[i].state == IPWD_DEVICE_STATE_UNUSABLE)
			continue;

		if (testing_flag == 0)
		{
			/* Check if received packet causes conflict with IP address of this interface */
			if (!((strcasecmp (rcv_sip, devices.dev[i].ip) == 0) && (strcasecmp (rcv_smac, devices.dev[i].mac) != 0)))
			{
				ipwd_message (IPWD_MSG_TYPE_DEBUG, "Packet does not conflict with: %s %s-%s", devices.dev[i].device, devices.dev[i].ip, devices.dev[i].mac);
				continue;
			}
		}

		/* Get current system time */
		if (gettimeofday (&current_time, NULL) != 0)
		{
			ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to get current time");
			break;
		}

		difference = ((current_time.tv_sec + (current_time.tv_usec / 1000000.0)) - (devices.dev[i].time.tv_sec + (devices.dev[i].time.tv_usec / 1000000.0)));

		/* Check if current time is within the defend interval */
		if (difference < config.defend_interval)
		{
			ipwd_message (IPWD_MSG_TYPE_ALERT, "MAC address %s causes IP conflict with address %s set on interface %s - no action taken because this happened within the defend interval", rcv_smac, devices.dev[i].ip, devices.dev[i].device);
			break;
		}

		/* Store conflict time */
		devices.dev[i].time.tv_sec = current_time.tv_sec;
		devices.dev[i].time.tv_usec = current_time.tv_usec;

		/* Handle IP conflict */
		if (devices.dev[i].mode == IPWD_PROTECTION_MODE_ACTIVE)
		{
			ipwd_message (IPWD_MSG_TYPE_ALERT, "MAC address %s causes IP conflict with address %s set on interface %s - active mode - reply sent", rcv_smac, devices.dev[i].ip, devices.dev[i].device);

			/* Send reply to conflicting system */
			ipwd_genarp (devices.dev[i].device, devices.dev[i].ip, devices.dev[i].mac, rcv_sip, rcv_smac, ARPOP_REPLY);

			/* Send GARP request to update cache of our neighbours */
			ipwd_genarp (devices.dev[i].device, devices.dev[i].ip, devices.dev[i].mac, devices.dev[i].ip, "ff:ff:ff:ff:ff:ff", ARPOP_REQUEST);
		}
		else
		{
			ipwd_message (IPWD_MSG_TYPE_ALERT, "MAC address %s causes IP conflict with address %s set on interface %s - passive mode - reply not sent", rcv_smac, devices.dev[i].ip, devices.dev[i].device);
		}

		if (config.script != NULL)
		{
			/* Run user-defined script in form: script "dev" "ip" "mac" */
			command_len = strlen (config.script) + 2 + strlen (devices.dev[i].device) + 3 + strlen (devices.dev[i].ip) + 3 + strlen (rcv_smac) + 2;

			if ((command = (char *) malloc (command_len * sizeof (char))) == NULL)
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to execute user-defined script - malloc failed");
				break;
 			}

			snprintf (command, command_len, "%s \"%s\" \"%s\" \"%s\"", config.script, devices.dev[i].device, devices.dev[i].ip, rcv_smac);

			ipwd_message (IPWD_MSG_TYPE_DEBUG, "Running user-defined script: %s", command);

			rv = system (command);
			if (rv == -1)
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to execute user-defined script: %s", command);
			}

			free (command);
			command = NULL;
		}
		else
		{
			ipwd_message (IPWD_MSG_TYPE_DEBUG, "No user-defined script specified");
		}

		if (testing_flag == 1)
		{
			break;
		}

	}
}

