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

/** \file ipwatchd.h
 * \brief Main header file of the project
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


//! String with IPwatchD version information
#define IPWATCHD_VERSION "IPwatchD 1.0.1"


/* Return values */

//! "Success" return value of IPwatchD internal functions
#define IPWD_RV_SUCCESS 0

//! "Error" return value of IPwatchD internal functions
#define IPWD_RV_ERROR   2


/* Message options */

//! Size of buffer for output messages
#define IPWD_MSG_BUFSIZ  1000

//! Message type: information
#define IPWD_MSG_INFO    1

//! Message type: error
#define IPWD_MSG_ERROR   2

//! Message type: alert
#define IPWD_MSG_ALERT   3

//! Message type: debug
#define IPWD_MSG_DEBUG   4


/* Operation modes */

//! Indicates that IPwatchD should operate in active mode on selected device
#define IPWD_MODE_ACTIVE  1

//! Indicates that  IPwatchD should operate in passive mode on selected device
#define IPWD_MODE_PASSIVE 2


/* Structures for network device information */

//! Structure that holds information about ONE network interface
typedef struct
{
	char device[10];	/**< Device name */
	char ip[20];		/**< IP address of device */
	char mac[20];		/**< MAC address of device */
	int mode;			/**< IPwatch mode on interface: IPWATCHD_DEVICE_MODE_ACTIVE or IPWATCHD_DEVICE_MODE_PASSIVE */
}
IPWD_S_DEV;

//! Structure that holds information about ALL network interfaces
typedef struct
{
	IPWD_S_DEV *dev;	/**< Dynamicaly allocated array of IPWD_S_DEV structures */
	int devnum;			/**< Number of watched interfaces */
}
IPWD_S_DEVS;


/* ARP packet information */

//! Number of useless bytes in ARP packet
/*! Parsing of packets captured by libpcap on pseudo device "any" seems to be
 * slightly different than parsing of packets captured on one particular interface.
 * Instead of usual 14th byte addresses begin on 24th byte of ARP header.
 */
#define IPWD_ARP_HEADER_SIZE 24

//! Structure useful for parsing of individual addresses from packet
typedef struct
{
	u_int8_t arp_sha[ETH_ALEN];		/**< Source MAC address */
	u_int8_t arp_spa[4];			/**< Source IP address */
	u_int8_t arp_tha[ETH_ALEN];		/**< Destination MAC address */
	u_int8_t arp_tpa[4];			/**< Destination IP address */
}
IPWD_S_ARP_HEADER;


/* IPwatchD internal functions - described in corresponding source files */

// \cond - Doxygen ignore block start

/* analyse.c */
void ipwd_analyse (u_char * args, const struct pcap_pkthdr *header, const u_char * packet);

/* config.c */
int ipwd_file_exists (char *filename);
int ipwd_read_config (char *filename);

/* daemonize.c */
int ipwd_daemonize (void);

/* desktop.c */
void ipwd_desktop_notification (char *message);

/* devinfo.c */
int ipwd_devinfo (char *p_dev, char *p_ip, char *p_mac);

/* genarp.c */
int ipwd_genarp (char *dev, char *p_sip, char *p_smac, char *p_dip, char *p_dmac, int opcode);

/* ipwatchd.c */
void ipwd_print_help (void);

/* message.c */
void ipwd_message (char *msg, int type);

/* signal.c */
int ipwd_set_signal_handler (void);
void ipwd_signal_handler (int signal);

// \endcond - Doxygen ignore block end

