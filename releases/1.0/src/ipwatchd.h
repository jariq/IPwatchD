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
 
 
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <syslog.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <libnet.h>
#include <pcap.h>


#define IPWATCHD_VERSION "IPwatchD 1.0"


/* Global return values */
#define IPWD_RV_SUCCESS 0         /* Return Value Success */
#define IPWD_RV_ERROR   2         /* Return Value Error */


/* Messages */
#define IPWD_MSG_BUFSIZ  1000     /* Size of buffer for output messages */
#define IPWD_MSG_INFO    1        /* Message type: information */
#define IPWD_MSG_ERROR   2        /* Message type: error */
#define IPWD_MSG_ALERT   3        /* Message type: alert */


/* Modes */
#define IPWD_MODE_ACTIVE  1       /* IPwatchD should operate in active mode */
#define IPWD_MODE_PASSIVE 2       /* IPwatchD should operate in passive mode */

/* Structure that holds information about ONE network interface */
typedef struct {

  char device[10];  /* Device name */
  char ip[20];      /* IP address of device */
  char mac[20];     /* MAC address of device */
  int mode;         /* IPwatch mode on interface: IPWATCHD_DEVICE_MODE_ACTIVE or IPWATCHD_DEVICE_MODE_PASSIVE */

} IPWD_S_DEV;

/* Structure that holds information about ALL network interfaces */
typedef struct {
	
	IPWD_S_DEV *dev;   /* Dynamicaly allocated array of IPWD_S_DEV structures */
	int devnum;        /* Number of watched interfaces */
	
} IPWD_S_DEVS;


/* Parsing of packets captured by libpcap on pseudo device "any" seems to be
 * slightly different than parsing of packets captured on one particular interface.
 * Instead of usual 14th byte addresses begin on 24th byte of ARP header. */
#define IPWD_ARP_HEADER_SIZE 24

/* Structure for parsing of addresses from packet */
typedef struct {

	u_int8_t arp_sha[ETH_ALEN];	 /* Source MAC address */
	u_int8_t arp_spa[4];		 /* Source IP address */
	u_int8_t arp_tha[ETH_ALEN];	 /* Destination MAC address */
	u_int8_t arp_tpa[4];		 /* Destination IP address */
	
} IPWD_S_ARP_HEADER;


/* Functions from IPwatchD modules - described in corresponding source file. */

/* analyse.c */
void ipwd_analyse(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/* config.c */
int ipwd_file_exists(char * filename);
int ipwd_read_config(char *filename);

/* daemonize.c */
int ipwd_daemonize(void);

/* devinfo.c */
int ipwd_devinfo(char *p_dev, char *p_ip, char *p_mac);

/* genarp.c */
int ipwd_genarp(char *dev, char *p_sip, char *p_smac, char *p_dip, char *p_dmac, int opcode);

/* ipwatchd.c */
void ipwd_signal_sigint();
void ipwd_print_help(void);

/* message.c */
void ipwd_message(char *msg, int type);

