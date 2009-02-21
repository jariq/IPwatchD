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
	IPWD_S_DEV temp_device;
	config_t conf;
	const char * pChar = NULL;
	config_setting_t * devs = NULL;
	config_setting_t * dev = NULL;
	config_setting_t * param = NULL;
	int devnum = 0;
	int i = 0;
	pcap_t *h_pcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];


	/* Initialize structures with default values */
	config.facility = LOG_DAEMON;
	config.script = NULL;
	config.defend_interval = 0;
	devices.dev = NULL;
	devices.devnum = 0;

	config_init (&conf);

	if (config_read_file (&conf, filename) != CONFIG_TRUE)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error at line %d - %s", config_error_line (&conf), config_error_text (&conf));
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Get and validate ipwatchd.facility - syslog facility */
	if ((pChar = config_lookup_string (&conf, "ipwatchd.facility")) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : ipwatchd.facility not found");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}
	
	if (strcmp (pChar, "auth") == 0)
	{
		config.facility  = LOG_AUTH;
	}
	else if (strcmp (pChar, "authpriv") == 0)
	{
		config.facility = LOG_AUTHPRIV;
	}
	else if (strcmp (pChar, "cron") == 0)
	{
		config.facility = LOG_CRON;
	}
	else if (strcmp (pChar, "daemon") == 0)
	{
		config.facility = LOG_DAEMON;
	}
	else if (strcmp (pChar, "kern") == 0)
	{
		config.facility = LOG_KERN;
	}
	else if (strcmp (pChar, "lpr") == 0)
	{
		config.facility = LOG_LPR;
	}
	else if (strcmp (pChar, "mail") == 0)
	{
		config.facility = LOG_MAIL;
	}
	else if (strcmp (pChar, "news") == 0)
	{
		config.facility = LOG_NEWS;
	}
	else if (strcmp (pChar, "syslog") == 0)
	{
		config.facility = LOG_SYSLOG;
	}
	else if (strcmp (pChar, "user") == 0)
	{
		config.facility = LOG_USER;
	}
	else if (strcmp (pChar, "uucp") == 0)
	{
		config.facility = LOG_UUCP;
	}
	else if (strcmp (pChar, "local0") == 0)
	{
		config.facility = LOG_LOCAL0;
	}
	else if (strcmp (pChar, "local1") == 0)
	{
		config.facility = LOG_LOCAL1;
	}
	else if (strcmp (pChar, "local2") == 0)
	{
		config.facility = LOG_LOCAL2;
	}
	else if (strcmp (pChar, "local3") == 0)
	{
		config.facility = LOG_LOCAL3;
	}
	else if (strcmp (pChar, "local4") == 0)
	{
		config.facility = LOG_LOCAL4;
	}
	else if (strcmp (pChar, "local5") == 0)
	{
		config.facility = LOG_LOCAL5;
	}
	else if (strcmp (pChar, "local6") == 0)
	{
		config.facility = LOG_LOCAL6;
	}
	else if (strcmp (pChar, "local7") == 0)
	{
		config.facility = LOG_LOCAL7;
	}
	else
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : %s as a value of ipwatchd.facility is not supported", pChar);
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Get and validate ipwatchd.script - path to user-defined script */
	if ((pChar = config_lookup_string (&conf, "ipwatchd.script")) != NULL)
	{
		if (ipwd_file_exists (pChar) == IPWD_RV_ERROR)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : file %s specified as ipwatchd.script does not exist", pChar);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}
		
		if ((config.script = (char *) malloc ((strlen (pChar) + 1) * sizeof (char))) == NULL)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : malloc for ipwatchd.script failed");
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		strcpy (config.script, pChar);
	}
	
	/* Get and validate ipwatchd.defend_interval - minimum interval between defensive ARPs */
	config.defend_interval = config_lookup_int (&conf, "ipwatchd.defend_interval");

	if ((config.defend_interval < 0) || (config.defend_interval > 600))
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : ipwatchd.defend_interval value must be between 0 and 600");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Get configuration parameters for ipwatchd.devices */
	if ((devs = config_lookup (&conf, "ipwatchd.devices")) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : list ipwatchd.devices not found");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	if (config_setting_type (devs) != CONFIG_TYPE_LIST)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : ipwatchd.devices must be list");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	devnum = config_setting_length (devs);
	
	if (devnum <= 0)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : no devices specified");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	for (i = 0; i < devnum; i++)
	{
		dev = config_setting_get_elem (devs, i);

		if (config_setting_type (dev) != CONFIG_TYPE_GROUP)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : ipwatchd.devices.[%d] must be group", i);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		/* Get and validate ipwatchd.devices.[i].device */
		if ((param = config_setting_get_member (dev, "device")) == NULL)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : ipwatchd.devices.[%d].device not found", i);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		if (config_setting_type (param) != CONFIG_TYPE_STRING)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : ipwatchd.devices.[%d].device must be string", i);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		snprintf (temp_device.device, sizeof (temp_device.device), "%s", config_setting_get_string (param));

		h_pcap = pcap_open_live (temp_device.device, BUFSIZ, 0, 0, errbuf);
		if (h_pcap == NULL)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "IPwatchD is unable to work with device \"%s\"", temp_device.device);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		if (pcap_datalink (h_pcap) != DLT_EN10MB)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Device \"%s\" is not valid ethernet device", temp_device.device);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		pcap_close (h_pcap);

		/* Get and validate ipwatchd.devices.[i].mode */
		if ((param = config_setting_get_member (dev, "mode")) == NULL)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : ipwatchd.devices.[%d].mode not found", i);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		if (config_setting_type (param) != CONFIG_TYPE_STRING)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : ipwatchd.devices.[%d].param must be string", i);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			return (IPWD_RV_ERROR);
		}

		if (strcmp (config_setting_get_string (param), "active") == 0)
		{
			temp_device.mode = IPWD_MODE_ACTIVE;
		}
		else if (strcmp (config_setting_get_string (param), "passive") == 0)
		{
			temp_device.mode = IPWD_MODE_PASSIVE;
		}
		else
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Configuration parse error : ipwatchd.devices.[%d].mode is not supported", i);
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

		strcpy (devices.dev[devices.devnum].device, temp_device.device);
		devices.dev[devices.devnum].mode = temp_device.mode;
		devices.dev[devices.devnum].time.tv_sec = 0;
		devices.dev[devices.devnum].time.tv_usec = 0;
		
		devices.devnum = devices.devnum + 1;
	}

	config_destroy (&conf);

	return (IPWD_RV_SUCCESS);
}

