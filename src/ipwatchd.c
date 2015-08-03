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

/** \file ipwatchd.c
 * \brief Main source file of the project
 */

#include "ipwatchd.h"


//! Flag indicating debug mode
int debug_flag = 0;

//! Flag indicating that output of program must be recorded by syslog
int syslog_flag = 0;

//! Flag indicating testing mode when every ARP packet is considered to be conflicting
int testing_flag = 0;

//! Structure that holds information about network interfaces
IPWD_S_DEVS devices;

//! Structure that holds values of particular configuration variables
IPWD_S_CONFIG config;

//! Handle for libpcap
pcap_t *h_pcap = NULL;


//! Main function of the ipwatchd program
/*!
 * \param argc Number of received command line arguments
 * \param argv Argument values
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int main (int argc, char *argv[])
{
	/* Name of configuration file  */
	char *config_file = NULL;

	int c = 0;
	int option_index = 0;

	/* Open connection to syslog with default daemon facility */
	openlog ("ipwatchd", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);

	/* Parse command line arguments */
	while (1)
	{
		static struct option long_options[] = {
			{ "config", required_argument, 0, 'c' },
			{ "debug", no_argument, 0, 'd' },
			{ "test", no_argument, 0, 't' },
			{ "help", no_argument, 0, 'h' },
			{ "version", no_argument, 0, 'v' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long (argc, argv, "c:dthv", long_options, &option_index);

		if (c == -1)
		{
			break;
		}

		switch (c)
		{
			case 'c':
				if (ipwd_file_exists (optarg) == IPWD_RV_ERROR)
				{
					ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to open configuration file %s", optarg);
					return (IPWD_RV_ERROR);
				}

				if ((config_file = (char *) malloc ((strlen (optarg) + 1) * sizeof (char))) == NULL)
				{
					ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to open configuration file %s - malloc failed", optarg);
					return (IPWD_RV_ERROR);
				}

				strcpy (config_file, optarg);
				break;

			case 'd':
				debug_flag = 1;
				break;

			case 't':
				testing_flag = 1;
				break;

			case 'h':
				ipwd_print_help ();
				return (IPWD_RV_SUCCESS);

			case 'v':
				ipwd_message (IPWD_MSG_TYPE_INFO, IPWATCHD_VERSION);
				return (IPWD_RV_SUCCESS);

			case '?':
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Try %s --help", argv[0]);
				return (IPWD_RV_ERROR);

			default:
				ipwd_print_help ();
				return (IPWD_RV_ERROR);
		}

	}

	/* Print help if there is any unknown argument */
	if (optind < argc)
	{
		ipwd_print_help ();
		return (IPWD_RV_ERROR);
	}

	/* Path to configuration file must be specified */
	if (config_file == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "You must specify path to configuration file.");
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Try %s --help", argv[0]);
		return (IPWD_RV_ERROR);
	}

	/* Only root can run IPwatchD */
	if (getuid () != 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "You must be root to run IPwatchD");
		return (IPWD_RV_ERROR);
	}

	/* Read config file */
	if (ipwd_read_config (config_file) == IPWD_RV_ERROR)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to read configuration file");
		return (IPWD_RV_ERROR);
	}

	free (config_file);
	config_file = NULL;

	/* Daemonize */
	if (ipwd_daemonize () != IPWD_RV_SUCCESS)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to daemonize");
		return (IPWD_RV_ERROR);
	}

	ipwd_message (IPWD_MSG_TYPE_INFO, "IPwatchD started");

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;

	/* Check if "any" pseudodevice is available */
	/* IPwatchD cannot be used on Debian GNU/kFreeBSD because of the lack of this device */
	pcap_if_t * pcap_alldevs = NULL;
	pcap_if_t * pcap_dev = NULL;
	int any_exists = 0;

	if (pcap_findalldevs(&pcap_alldevs, errbuf))
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to get network device list - %s", errbuf);
		return (IPWD_RV_ERROR);
	}

	for (pcap_dev = pcap_alldevs; pcap_dev; pcap_dev = pcap_dev->next)
	{
		if (strcasecmp (pcap_dev->name, "any") == 0)
		{
			any_exists = 1;
			break;
		}
	}

	if (!any_exists)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Pseudodevice \"any\" used by libpcap is not available");
		return (IPWD_RV_ERROR);
	}

	/* Initialize libpcap and listen on all interfaces */
	h_pcap = pcap_open_live ("any", BUFSIZ, 0, 0, errbuf);
	if (h_pcap == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to create packet capture object - %s", errbuf);
		return (IPWD_RV_ERROR);
	}

	/* Set SIGTERM handler */
	if (ipwd_set_signal_handler () != IPWD_RV_SUCCESS)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to set signal handlers");
		return (IPWD_RV_ERROR);
	}

	/* Compile packet capture filter - only ARP packets will be captured */
	if (pcap_compile (h_pcap, &fp, "arp", 0, 0) == -1)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to compile packet capture filter - %s", pcap_geterr (h_pcap));
		return (IPWD_RV_ERROR);
	}

	/* Set packet capture filter */
	if (pcap_setfilter (h_pcap, &fp) == -1)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to set packet capture filter - %s", pcap_geterr (h_pcap));
		return (IPWD_RV_ERROR);
	}

	pcap_freecode (&fp);

	ipwd_message (IPWD_MSG_TYPE_DEBUG, "Entering pcap loop");

	/* Loop until SIGTERM calls pcap_breakloop */
	pcap_loop (h_pcap, -1, ipwd_analyse, NULL);

	pcap_close (h_pcap);

	/* Stop IPwatchD */
	ipwd_message (IPWD_MSG_TYPE_INFO, "IPwatchD stopped");

	closelog ();

	if (config.script != NULL)
	{
		free (config.script);
		config.script = NULL;
	}

	if (devices.dev != NULL)
	{
		free (devices.dev);
		devices.dev = NULL;
	}

	return (IPWD_RV_SUCCESS);
}


//! Prints help to the stdout
void ipwd_print_help (void)
{
	fprintf (stdout, "IPwatchD - IP conflict detection tool for Linux\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "IPwatchD is simple daemon that analyses all incoming ARP\n");
	fprintf (stdout, "packets in order to detect IP conflicts.\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "Usage: ipwatchd --config config_file [--debug] [--test]\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "  -c | --config config_file    - Path to configuration file\n");
	fprintf (stdout, "  -d | --debug                 - Run in debug mode\n");
	fprintf (stdout, "  -t | --test                  - Run in testing mode\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "or     ipwatchd --version|--help\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "  -v | --version               - Prints program version\n");
	fprintf (stdout, "  -v | --help                  - Displays this help message\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "Please send any bug reports to jariq@jariq.sk\n");
}

