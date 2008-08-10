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

/** \file config.c
 * \brief Contains logic used for parsing of configuration
 */


#include "ipwatchd.h"


extern int debug_flag;
extern IPWD_S_DEVS devices;
extern char msgbuf[IPWD_MSG_BUFSIZ];


//! Checks existence of the file
/*!
 * \param filename Path to the file
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_file_exists (char *filename)
{

	FILE *fr = NULL;

	if ((fr = fopen (filename, "r")) == NULL)
	{
		return (IPWD_RV_ERROR);
	}

	if (fclose (fr) == EOF)
	{
		return (IPWD_RV_ERROR);
	}

	return (IPWD_RV_SUCCESS);

}


//! Reads configuration file and stores names of interfaces into the "devices" structure
/*!
 * \param filename Path to the configurationfile
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_read_config (char *filename)
{

	FILE *fr = NULL;

	char line[255];
	int linenum = 0;

	char device[10];
	char mode[10];

	pcap_t *h_pcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Starting with empty devices structure */
	devices.dev = NULL;
	devices.devnum = 0;

	if ((fr = fopen (filename, "r")) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to open configuration file %s", filename);
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Parse config file */
	while (fgets (line, 254, fr) != NULL)
	{

		linenum = linenum + 1;

		device[0] = '\0';
		mode[0] = '\0';

		if ((line[0] == '#') || (line[0] == '\n'))
		{
			continue;
		}

		if (sscanf (line, "%9s %9s", device, mode) != 2)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Not enough parameters in configuration file on line %d", linenum);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		/* Check if device is valid ethernet device */
		h_pcap = pcap_open_live (device, BUFSIZ, 0, 0, errbuf);
		if (h_pcap == NULL)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "IPwatchD is unable to work with device \"%s\"", device);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		if (pcap_datalink (h_pcap) != DLT_EN10MB)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Device \"%s\" is not valid ethernet device", device);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		pcap_close (h_pcap);

		/* Check mode value */
		if ((strcmp (mode, "active") != 0) && (strcmp (mode, "passive") != 0))
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Mode \"%s\" on line %d in configuration file not supported", mode, linenum);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		/* Put read values into devices structure */
		if ((devices.dev = (IPWD_S_DEV *) realloc (devices.dev, (devices.devnum + 1) * sizeof (IPWD_S_DEV))) == NULL)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to initialize devices structure");
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		strcpy (devices.dev[devices.devnum].device, device);

		if (strcmp (mode, "active") == 0)
		{
			devices.dev[devices.devnum].mode = IPWD_MODE_ACTIVE;
		}
		else
		{
			devices.dev[devices.devnum].mode = IPWD_MODE_PASSIVE;
		}

		devices.devnum = devices.devnum + 1;

		line[0] = '\0';

	}

	if (fclose (fr) == EOF)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to close configuration file %s", filename);
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	return (IPWD_RV_SUCCESS);

}

