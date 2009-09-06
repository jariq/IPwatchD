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

/** \file config.c
 * \brief Contains logic used for parsing of configuration
 */


#include "ipwatchd.h"


extern int debug_flag;
extern IPWD_S_DEVS devices;
extern char msgbuf[IPWD_MSG_BUFSIZ];
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
 * \param filename Path to the configurationfile
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
	devices.dev = NULL;
	devices.devnum = 0;

	if ((fr = fopen (filename, "r")) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to open configuration file %s", filename);
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Parse config file */
	while (fgets (line, 499, fr) != NULL)
	{

		linenum = linenum + 1;

		variable[0] = '\0';
		value[0] = '\0';

		if ((line[0] == '#') || (line[0] == '\n'))
		{
			continue;
		}

		if (sscanf (line, "%99s %399s", variable, value) != 2)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Not enough parameters in configuration file on line %d", linenum);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		/* Syslog Facility */
		if (strcmp (variable, "syslog_facility") == 0)
		{
			if (strcmp (value, "auth") == 0)
			{
				config.facility  = LOG_AUTH;
				continue;
			}
			else if (strcmp (value, "authpriv") == 0)
			{
				config.facility = LOG_AUTHPRIV;
				continue;
			}
			else if (strcmp (value, "cron") == 0)
			{
				config.facility = LOG_CRON;
				continue;
			}
			else if (strcmp (value, "daemon") == 0)
			{
				config.facility = LOG_DAEMON;
				continue;
			}
			else if (strcmp (value, "kern") == 0)
			{
				config.facility = LOG_KERN;
				continue;
			}
			else if (strcmp (value, "lpr") == 0)
			{
				config.facility = LOG_LPR;
				continue;
			}
			else if (strcmp (value, "mail") == 0)
			{
				config.facility = LOG_MAIL;
				continue;
			}
			else if (strcmp (value, "news") == 0)
			{
				config.facility = LOG_NEWS;
				continue;
			}
			else if (strcmp (value, "syslog") == 0)
			{
				config.facility = LOG_SYSLOG;
				continue;
			}
			else if (strcmp (value, "user") == 0)
			{
				config.facility = LOG_USER;
				continue;
			}
			else if (strcmp (value, "uucp") == 0)
			{
				config.facility = LOG_UUCP;
				continue;
			}
			else if (strcmp (value, "local0") == 0)
			{
				config.facility = LOG_LOCAL0;
				continue;
			}
			else if (strcmp (value, "local1") == 0)
			{
				config.facility = LOG_LOCAL1;
				continue;
			}
			else if (strcmp (value, "local2") == 0)
			{
				config.facility = LOG_LOCAL2;
				continue;
			}
			else if (strcmp (value, "local3") == 0)
			{
				config.facility = LOG_LOCAL3;
				continue;
			}
			else if (strcmp (value, "local4") == 0)
			{
				config.facility = LOG_LOCAL4;
				continue;
			}
			else if (strcmp (value, "local5") == 0)
			{
				config.facility = LOG_LOCAL5;
				continue;
			}
			else if (strcmp (value, "local6") == 0)
			{
				config.facility = LOG_LOCAL6;
				continue;
			}
			else if (strcmp (value, "local7") == 0)
			{
				config.facility = LOG_LOCAL7;
				continue;
			}
			else
			{
				snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : %s as a value of syslog_facility is not supported", value);
				ipwd_message (msgbuf, IPWD_MSG_ERROR);
				return (IPWD_RV_ERROR);
			}
		}

		/* Path to user-defined script */
		if (strcmp (variable, "user_script") == 0)
		{
			if (ipwd_file_exists (value) == IPWD_RV_ERROR)
			{
				snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : file %s specified as user_script does not exist", value);
				ipwd_message (msgbuf, IPWD_MSG_ERROR);
				return (IPWD_RV_ERROR);
			}
	
			if ((config.script = (char *) malloc ((strlen (value) + 1) * sizeof (char))) == NULL)
			{
				snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : malloc for user_script failed");
				ipwd_message (msgbuf, IPWD_MSG_ERROR);
				return (IPWD_RV_ERROR);
			}

			strcpy (config.script, value);
			continue;
		}

		/* Minimum interval between defensive ARPs */
		if (strcmp (variable, "defend_interval") == 0)
		{
			config.defend_interval = strtol (value, NULL, 10);

			if ((config.defend_interval < 0) || (config.defend_interval > 600))
			{
				snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : defend_interval value must be between 0 and 600");
				ipwd_message (msgbuf, IPWD_MSG_ERROR);
				return (IPWD_RV_ERROR);
			}

			continue;
		}
	
		/* ALL OTHER UNCOMMENTED LINES MUST SPECIFY INTERFACES */
		
		/* Check if device is valid ethernet device */
		h_pcap = pcap_open_live (variable, BUFSIZ, 0, 0, errbuf);
		if (h_pcap == NULL)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "IPwatchD is unable to work with device \"%s\"", variable);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		if (pcap_datalink (h_pcap) != DLT_EN10MB)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Device \"%s\" is not valid ethernet device", variable);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		pcap_close (h_pcap);

		/* Check mode value */
		if ((strcmp (value, "active") != 0) && (strcmp (value, "passive") != 0))
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Mode \"%s\" on line %d in configuration file not supported", value, linenum);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		/* Put read values into devices structure */
		if ((devices.dev = (IPWD_S_DEV *) realloc (devices.dev, (devices.devnum + 1) * sizeof (IPWD_S_DEV))) == NULL)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to resize devices structure");
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		strncpy (devices.dev[devices.devnum].device, variable, 9);
		*(devices.dev[devices.devnum].device + 9) = '\0';

		if (strcmp (value, "active") == 0)
		{
			devices.dev[devices.devnum].mode = IPWD_MODE_ACTIVE;
		}
		else
		{
			devices.dev[devices.devnum].mode = IPWD_MODE_PASSIVE;
		}

		/* Set time of last conflict */
		devices.dev[devices.devnum].time.tv_sec = 0;
		devices.dev[devices.devnum].time.tv_usec = 0;

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

