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

/** \file config.c
 * \brief Contains logic used for parsing of configuration
 */


#include "ipwatchd.h"


extern int debug_flag;
extern IPWD_S_DEVS devices;
extern IPWD_S_CONFIG config;


//! Checks existence of the file
/*!
 * \param filename Path to the file
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_file_exists (const char *filename)
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
 * \param filename Path to the configuration file
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_read_config (const char *filename)
{

	FILE *fr = NULL;

	char line[500];
	int linenum = 0;

	char variable[100];
	char value[400];

	pcap_t *h_pcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	// Initialize structures with default values
	config.facility = LOG_DAEMON;
	config.script = NULL;
	config.defend_interval = 0;
	config.mode = IPWD_CONFIGURATION_MODE_AUTOMATIC;
	devices.dev = NULL;
	devices.devnum = 0;

	if ((fr = fopen (filename, "r")) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to open configuration file %s", filename);
		return (IPWD_RV_ERROR);
	}

	memset (line, 0, sizeof (line));

	/* Parse config file */
	while (fgets (line, 499, fr) != NULL)
	{

		linenum = linenum + 1;

		memset (variable, 0, sizeof (variable));
		memset (value, 0, sizeof (value));

		if ((line[0] == '#') || (line[0] == '\n'))
		{
			continue;
		}

		if (sscanf (line, "%99s %399s", variable, value) != 2)
		{
			ipwd_message (IPWD_MSG_TYPE_ERROR, "Not enough parameters in configuration file on line %d", linenum);
			return (IPWD_RV_ERROR);
		}

		/* Syslog Facility */
		if (strcasecmp (variable, "syslog_facility") == 0)
		{
			if (strcasecmp (value, "auth") == 0)
			{
				config.facility  = LOG_AUTH;
				continue;
			}
			else if (strcasecmp (value, "authpriv") == 0)
			{
				config.facility = LOG_AUTHPRIV;
				continue;
			}
			else if (strcasecmp (value, "cron") == 0)
			{
				config.facility = LOG_CRON;
				continue;
			}
			else if (strcasecmp (value, "daemon") == 0)
			{
				config.facility = LOG_DAEMON;
				continue;
			}
			else if (strcasecmp (value, "kern") == 0)
			{
				config.facility = LOG_KERN;
				continue;
			}
			else if (strcasecmp (value, "lpr") == 0)
			{
				config.facility = LOG_LPR;
				continue;
			}
			else if (strcasecmp (value, "mail") == 0)
			{
				config.facility = LOG_MAIL;
				continue;
			}
			else if (strcasecmp (value, "news") == 0)
			{
				config.facility = LOG_NEWS;
				continue;
			}
			else if (strcasecmp (value, "syslog") == 0)
			{
				config.facility = LOG_SYSLOG;
				continue;
			}
			else if (strcasecmp (value, "user") == 0)
			{
				config.facility = LOG_USER;
				continue;
			}
			else if (strcasecmp (value, "uucp") == 0)
			{
				config.facility = LOG_UUCP;
				continue;
			}
			else if (strcasecmp (value, "local0") == 0)
			{
				config.facility = LOG_LOCAL0;
				continue;
			}
			else if (strcasecmp (value, "local1") == 0)
			{
				config.facility = LOG_LOCAL1;
				continue;
			}
			else if (strcasecmp (value, "local2") == 0)
			{
				config.facility = LOG_LOCAL2;
				continue;
			}
			else if (strcasecmp (value, "local3") == 0)
			{
				config.facility = LOG_LOCAL3;
				continue;
			}
			else if (strcasecmp (value, "local4") == 0)
			{
				config.facility = LOG_LOCAL4;
				continue;
			}
			else if (strcasecmp (value, "local5") == 0)
			{
				config.facility = LOG_LOCAL5;
				continue;
			}
			else if (strcasecmp (value, "local6") == 0)
			{
				config.facility = LOG_LOCAL6;
				continue;
			}
			else if (strcasecmp (value, "local7") == 0)
			{
				config.facility = LOG_LOCAL7;
				continue;
			}
			else
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Configuration parse error : %s as a value of syslog_facility is not supported", value);
				return (IPWD_RV_ERROR);
			}
		}

		/* Path to user-defined script */
		if (strcasecmp (variable, "user_script") == 0)
		{
			if (ipwd_file_exists (value) == IPWD_RV_ERROR)
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Configuration parse error : file %s specified as user_script does not exist", value);
				return (IPWD_RV_ERROR);
			}
	
			if ((config.script = (char *) malloc ((strlen (value) + 1) * sizeof (char))) == NULL)
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Configuration parse error : malloc for user_script failed");
				return (IPWD_RV_ERROR);
			}

			strcpy (config.script, value);
			continue;
		}

		/* Minimum interval between defensive ARPs */
		if (strcasecmp (variable, "defend_interval") == 0)
		{
			config.defend_interval = strtol (value, NULL, 10);

			if ((config.defend_interval < 0) || (config.defend_interval > 600))
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Configuration parse error : defend_interval value must be between 0 and 600");
				return (IPWD_RV_ERROR);
			}

			continue;
		}

		/* Configuration mode for network interfaces */
		if (strcasecmp (variable, "iface_configuration") == 0)
		{
			/* Check mode value */
			if ((strcasecmp (value, "automatic") != 0) && (strcasecmp (value, "manual") != 0))
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Configuration mode \"%s\" on line %d in configuration file not supported", value, linenum);
				return (IPWD_RV_ERROR);
			}

			/* Switch to manual mode if requested */
			if (strcasecmp (value, "manual") == 0)
			{
				config.mode = IPWD_CONFIGURATION_MODE_MANUAL;
				continue;
			}

			/* Automatic mode is default */
			if (ipwd_fill_devices () != IPWD_RV_SUCCESS)
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Automatic configuration mode failed. Please switch to manual configuration mode.");
				return (IPWD_RV_ERROR);
			}

			continue;
		}

		/* Monitored interfaces */
		if (strcasecmp (variable, "iface") == 0)
		{

			/* Check if configuration mode is manual */
			if (config.mode != IPWD_CONFIGURATION_MODE_MANUAL)
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Found iface variable in automatic configuration mode. Please check configuration file for logical errors");
				return (IPWD_RV_ERROR);
			}

			/* Read interface name and protection mode */
			if (sscanf (line, "%*s %93s %399s", variable, value) != 2)
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Not enough parameters in configuration file on line %d", linenum);
				return (IPWD_RV_ERROR);
			}
	
			/* Check if device is valid ethernet device */
			h_pcap = pcap_open_live (variable, BUFSIZ, 0, 0, errbuf);
			if (h_pcap == NULL)
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "IPwatchD is unable to work with interface \"%s\"", variable);
				return (IPWD_RV_ERROR);
			}

			if (pcap_datalink (h_pcap) != DLT_EN10MB)
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Device \"%s\" is not valid ethernet interface", variable);
				return (IPWD_RV_ERROR);
			}

			pcap_close (h_pcap);

			/* Check mode value */
			if ((strcasecmp (value, "active") != 0) && (strcasecmp (value, "passive") != 0))
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Protection mode \"%s\" on line %d in configuration file not supported", value, linenum);
				return (IPWD_RV_ERROR);
			}

			/* Put read values into devices structure */
			if ((devices.dev = (IPWD_S_DEV *) realloc (devices.dev, (devices.devnum + 1) * sizeof (IPWD_S_DEV))) == NULL)
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to resize devices structure");
				return (IPWD_RV_ERROR);
			}

			memset (devices.dev[devices.devnum].device, '\0', IPWD_MAX_DEVICE_NAME_LEN);
			strncpy (devices.dev[devices.devnum].device, variable, IPWD_MAX_DEVICE_NAME_LEN - 1);

			if (strcasecmp (value, "active") == 0)
			{
				devices.dev[devices.devnum].mode = IPWD_PROTECTION_MODE_ACTIVE;
			}
			else
			{
				devices.dev[devices.devnum].mode = IPWD_PROTECTION_MODE_PASSIVE;
			}

			/* Set time of last conflict */
			devices.dev[devices.devnum].time.tv_sec = 0;
			devices.dev[devices.devnum].time.tv_usec = 0;

			ipwd_message (IPWD_MSG_TYPE_DEBUG, "Found interface %s", devices.dev[devices.devnum].device);

			devices.devnum = devices.devnum + 1;

		}

		memset (line, 0, sizeof (line));

	}

	if (fclose (fr) == EOF)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to close configuration file %s", filename);
		return (IPWD_RV_ERROR);
	}

	/* Check number of discovered interfaces */
	if (devices.devnum < 1)
	{
		if (config.mode == IPWD_CONFIGURATION_MODE_MANUAL)
		{
			ipwd_message (IPWD_MSG_TYPE_ERROR, "No interfaces specified in configuration file");
			return (IPWD_RV_ERROR);
		}
		else
		{
			ipwd_message (IPWD_MSG_TYPE_ERROR, "No interfaces discovered");
			return (IPWD_RV_ERROR);
		}
	}

	return (IPWD_RV_SUCCESS);

}

