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

/** \file ipwatchd.c
 * \brief Main source file of the project
 */

#include "ipwatchd.h"


//! Flag indicating debug mode
int debug_flag = 0;

//! Flag indicating that output of program must be recorded by syslog
int syslog_flag = 0;

//! Structure that holds information about network interfaces
IPWD_S_DEVS devices;

//! Structure that holds information about available D-BUS buses
IPWD_S_BUSES buses;

//! Buffer for output messages
char msgbuf[IPWD_MSG_BUFSIZ];

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

	int c;
	int option_index = 0;

	/* Parse command line arguments */
	while (1)
    {

		static struct option long_options[] = {
			{ "config", required_argument, 0, 'c' },
			{ "debug", no_argument, &debug_flag, 1 },
			{ "help", no_argument, 0, 'h' },
			{ "version", no_argument, 0, 'v' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long (argc, argv, "c:dhv", long_options, &option_index);

		if (c == -1)
		{
			break;
		}

		switch (c)
		{

			case 0:
				/* If debug_flag is set do nothing */
				if (long_options[option_index].flag != 0)
				{
					break;
				}

			case 'c':
				if (ipwd_file_exists (optarg) == IPWD_RV_ERROR)
				{
					snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to open configuration file %s", optarg);
					ipwd_message (msgbuf, IPWD_MSG_ERROR);
					return (IPWD_RV_ERROR);
				}

				if ((config_file = (char *) malloc ((strlen (optarg) + 1) * sizeof (char))) == NULL)
				{
					snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to open configuration file %s", optarg);
					ipwd_message (msgbuf, IPWD_MSG_ERROR);
					return (IPWD_RV_ERROR);
				}

				strcpy (config_file, optarg);
				break;

			case 'd':
				debug_flag = 1;
				break;

			case 'h':
				ipwd_print_help ();
				return (IPWD_RV_SUCCESS);

			case 'v':
				snprintf (msgbuf, IPWD_MSG_BUFSIZ, "%s", IPWATCHD_VERSION);
				ipwd_message (msgbuf, IPWD_MSG_INFO);
				return (IPWD_RV_SUCCESS);

			case '?':
				snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Try %s --help", argv[0]);
				ipwd_message (msgbuf, IPWD_MSG_ERROR);
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
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "You must specify path to configuration file.");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Try %s --help", argv[0]);
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Only root can run IPwatchD */
	if (getuid () != 0)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "You must be root to run IPwatchD");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Read config file */
	if (ipwd_read_config (config_file) == IPWD_RV_ERROR)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to read configuration file");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	free (config_file);
	config_file = NULL;

	/* Daemonize */
	if (ipwd_daemonize () != IPWD_RV_SUCCESS)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to daemonize");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* All messages must be sysloged since now */
	openlog ("IPwatchD", LOG_PID, LOG_DAEMON);
	syslog_flag = 1;

	snprintf (msgbuf, IPWD_MSG_BUFSIZ, "IPwatchD started");
	ipwd_message (msgbuf, IPWD_MSG_INFO);

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;

	/* Initialize libpcap and listen on all interfaces */
	h_pcap = pcap_open_live (NULL, BUFSIZ, 0, 0, errbuf);
	if (h_pcap == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to create packet capture object - %s", errbuf);
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Set SIGTERM handler */
	if (ipwd_set_signal_handler () != IPWD_RV_SUCCESS)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to set signal handlers");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Compile packet capture filter - only ARP packets will be captured */
	if (pcap_compile (h_pcap, &fp, "arp", 0, 0) == -1)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to compile packet capture filter - %s", pcap_geterr (h_pcap));
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Set packet capture filter */
	if (pcap_setfilter (h_pcap, &fp) == -1)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to set packet capture filter - %s", pcap_geterr (h_pcap));
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	pcap_freecode (&fp);

	snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Entering pcap loop");
	ipwd_message (msgbuf, IPWD_MSG_DEBUG);

	/* Loop until SIGTERM or any error destroys pcap object */
	pcap_loop (h_pcap, -1, ipwd_analyse, NULL);

	/* Stop IPwatchD */
	snprintf (msgbuf, IPWD_MSG_BUFSIZ, "IPwatchD stopped");
	ipwd_message (msgbuf, IPWD_MSG_INFO);

	closelog ();

	free (devices.dev);

	return (IPWD_RV_SUCCESS);

}


//! Prints help to the stdout
void ipwd_print_help (void)
{
	fprintf (stdout, "IPwatchD - IP conflict detection tool for Linux\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "Usage: ipwatchd --config config_file [--debug]\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "  --config config_file    - Path to configuration file\n");
	fprintf (stdout, "  --debug                 - Run in debug mode\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "or     ipwatchd --version|--help\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "  --version               - Prints program version\n");
	fprintf (stdout, "  --help                  - Displays this help message\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "IPwatchD is simple daemon that uses pcap library to capture\n");
	fprintf (stdout, "all  incoming  ARP  packets. It  then  compares  IP and MAC\n");
	fprintf (stdout, "addresses from  packets with addresses of local  interfaces\n");
	fprintf (stdout, "trying to detect IP conflict.  IPwatchD can operate on each\n");
	fprintf (stdout, "network interface in two modes – passive and active.\n");
	fprintf (stdout, "In passive mode it just generates syslog events.  In active\n");
	fprintf (stdout, "mode  it  also  answers  Gratuitous  ARP  request and sends\n");
	fprintf (stdout, "following  Gratuitous  ARP  requests to update ARP cache of\n");
	fprintf (stdout, "neighboring hosts with correct data.\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "Please send any bug reports to jariq@jariq.sk\n");
}

