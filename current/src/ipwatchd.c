/* IPwatchD - IP conflict detection in Linux systems
 * Copyright (C) 2007 Jaroslav Imrich <jariq@jariq.sk>
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


#include "ipwatchd.h"


int          debug_flag  = 0;          /* Flag indicating debug mode */
int          syslog_flag = 0;          /* Flag indicating that output of program must be recorded by syslog */
IPWD_S_DEVS  devices;                  /* Structure that holds information about network interfaces */
char         msgbuf[IPWD_MSG_BUFSIZ];  /* Buffer for output messages */


static pcap_t *h_pcap = NULL;          /* Handle for libpcap */


/* IPwatchD main program */
int main(int argc, char *argv[]) {

  char *config_file = NULL;            /* Name of configuration file  */

  int  c;
  int  option_index = 0; 
  
  /* Parse command line arguments */
  while (1) {
  
    static struct option long_options[] = {

      { "config",  required_argument, 0,           'c' },
      { "debug",   no_argument,       &debug_flag,  1  },
      { "help",    no_argument,       0,           'h' },
      { "version", no_argument,       0,           'v' },
      { 0,         0,                 0,            0  }

    };

    c = getopt_long (argc, argv, "c:dhv", long_options, &option_index);
     
    if (c == -1) {
      break;
    }
     
    switch (c) {
      
      case 0:
        /* If debug_flag is set do nothing */
        if (long_options[option_index].flag != 0) {
          break;
        }
      
      case 'c':
        if (ipwd_file_exists(optarg) == IPWD_RV_ERROR) {
          snprintf(msgbuf, IPWD_MSG_BUFSIZ, "Unable to open configuration file %s.\n", optarg);
          ipwd_message(msgbuf, IPWD_MSG_ERROR);
          return(IPWD_RV_ERROR);
        }
        
        if ((config_file = (char *) malloc((strlen(optarg) + 1) * sizeof(char))) == NULL) {
          snprintf(msgbuf, IPWD_MSG_BUFSIZ, "Unable to open configuration file %s.\n", optarg);
          ipwd_message(msgbuf, IPWD_MSG_ERROR);
          return(IPWD_RV_ERROR);
        }
        
        strcpy(config_file, optarg);

        break;
      
      case 'd':
        debug_flag = 1;
        break;
      
      case 'h':
        ipwd_print_help();
        return(IPWD_RV_SUCCESS);
      
      case 'v':
        snprintf(msgbuf, IPWD_MSG_BUFSIZ, "%s\n", IPWATCHD_VERSION);
        ipwd_message(msgbuf, IPWD_MSG_INFO);
        return(IPWD_RV_SUCCESS);
      
      case '?':
        snprintf(msgbuf, IPWD_MSG_BUFSIZ, "Try %s --help\n", argv[0]);
        ipwd_message(msgbuf, IPWD_MSG_ERROR);
        return(IPWD_RV_ERROR);
      
      default:
        ipwd_print_help();
        return(IPWD_RV_ERROR);

    }
    
  }

  /* Print help if there is any unknown argument */
  if (optind < argc) {
    ipwd_print_help();
    return(IPWD_RV_ERROR);
  }

  /* Path to configuration file must be specified */
  if (config_file == NULL) {
    snprintf(msgbuf, IPWD_MSG_BUFSIZ, "You must specify path to configuration file.\nTry %s --help\n", argv[0]);
    ipwd_message(msgbuf, IPWD_MSG_ERROR);
    return(IPWD_RV_ERROR);
  }
  
  /* Only root can run IPwatchD */
  if (getuid() != 0) {
    snprintf(msgbuf, IPWD_MSG_BUFSIZ, "You must be root to run IPwatchD.\n");
    ipwd_message(msgbuf, IPWD_MSG_ERROR);
    return(IPWD_RV_ERROR);
  }
  
  /* Read config file */
  if (ipwd_read_config(config_file) == IPWD_RV_ERROR) {
    snprintf(msgbuf, IPWD_MSG_BUFSIZ, "Unable to read configuration file.\n");
    ipwd_message(msgbuf, IPWD_MSG_ERROR);
    return(IPWD_RV_ERROR);
  }
    
  free(config_file);
  config_file = NULL;

  /* Daemonize if not running in debug mode */
  if (!debug_flag) {
  	
    if (ipwd_daemonize() != IPWD_RV_SUCCESS) {
      snprintf(msgbuf, IPWD_MSG_BUFSIZ, "Unable to daemonize.\n");
      ipwd_message(msgbuf, IPWD_MSG_ERROR);
      return(IPWD_RV_ERROR);
    }

    /* All messages must be sysloged since now */
    openlog("IPwatchD", LOG_PID, LOG_DAEMON);
    syslog_flag = 1;
  
  }

  snprintf(msgbuf, IPWD_MSG_BUFSIZ, "IPwatchD started.\n");
  ipwd_message(msgbuf, IPWD_MSG_INFO);

  char errbuf[PCAP_ERRBUF_SIZE];	
  struct bpf_program fp;

  /* Initialize libpcap and listen on all interfaces */
  h_pcap = pcap_open_live(NULL, BUFSIZ, 0, 0, errbuf);
  if (h_pcap == NULL) {
    snprintf(msgbuf, IPWD_MSG_BUFSIZ, "Unable to create packet capture object - %s.\n", errbuf);
    ipwd_message(msgbuf, IPWD_MSG_ERROR);
    return(IPWD_RV_ERROR);
  }

  /* Set SIGINT handler */
  signal(SIGINT, ipwd_signal_sigint);

  /* Compile packet capture filter - only ARP packets will be captured */
  if (pcap_compile(h_pcap, &fp, "arp", 0, 0) == -1) {
    snprintf(msgbuf, IPWD_MSG_BUFSIZ, "Unable to compile packet capture filter - %s.\n", pcap_geterr(h_pcap));
    ipwd_message(msgbuf, IPWD_MSG_ERROR);
    return(IPWD_RV_ERROR);
  }

  /* Set packet capture filter */
  if (pcap_setfilter(h_pcap, &fp) == -1) {
    snprintf(msgbuf, IPWD_MSG_BUFSIZ, "Unable to set packet capture filter - %s.\n", pcap_geterr(h_pcap));
    ipwd_message(msgbuf, IPWD_MSG_ERROR);
    return(IPWD_RV_ERROR);
  }

  pcap_freecode(&fp);

  if (debug_flag) {
    snprintf(msgbuf, IPWD_MSG_BUFSIZ, "Entering pcap loop.\n");
    ipwd_message(msgbuf, IPWD_MSG_INFO);  	
  }

  /* Loop until SIGINT or any error destroys pcap object */
  pcap_loop(h_pcap, -1, ipwd_analyse, NULL);

  /* Stop IPwatchD */
  snprintf(msgbuf, IPWD_MSG_BUFSIZ, "IPwatchD stopped.\n");
  ipwd_message(msgbuf, IPWD_MSG_INFO);  

  closelog();

  free(devices.dev);

  return(IPWD_RV_SUCCESS);

}


/* SIGINT handler - called when SIGINT received */
void ipwd_signal_sigint() {
  
  if (debug_flag) {
    snprintf(msgbuf, IPWD_MSG_BUFSIZ, "SIGINT received.\n");
    ipwd_message(msgbuf, IPWD_MSG_INFO);  	
  }

  pcap_close(h_pcap);

}


/* Prints help to the stdout */
void ipwd_print_help(void) {

  printf("IPwatchD - IP conflict detection in Linux systems\n");
  printf("\n");
  printf("Usage: ipwatchd --config config_file [--debug]\n");
  printf("\n");
  printf("  --config config_file    - Path to configuration file\n"); 
  printf("  --debug                 - Run in debug mode\n");
  printf("\n");
  printf("or     ipwatchd --version|--help\n");  
  printf("\n");
  printf("  --version               - Prints program version\n"); 
  printf("  --help                  - Displays this help message\n");
  printf("\n");
  printf("If IPwatchD running in active mode (default) detects gratuitous\n");
  printf("ARP request with IP address of monitored interface (IP conflict)\n");
  printf("it immediately sends ARP reply to the conflicting host and also\n");
  printf("gratuitous ARP request to update cache of neighbouring hosts\n");
  printf("on local network.\n");
  printf("\n");
  printf("Please send any bug reports to jariq@jariq.sk\n");
  
}
