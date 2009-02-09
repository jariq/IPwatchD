/* IPwatchD G Notify - Notification tool for Gnome environment
 * Copyright (C) 2009 Jaroslav Imrich <jariq(at)jariq(dot)sk>
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

/** \file ipwatchd-gnotify.h
 * \brief Main header file of the project
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/wait.h>
#include <libnotify/notify.h>


//! String with IPwatchD G Notify version information
#define IPWATCHD_GNOTIFY_VERSION "IPwatchD G Notify 1.0"

//! Size of buffer for output messages
#define IPWDGN_MSG_BUFSIZ  1000

//! Size of buffer used for reading content of files
#define IPWDGN_FILE_BUFSIZ 1000


/* Return values */

//! "Success" return value of IPwatchD internal functions
#define IPWDGN_RV_SUCCESS 0

//! "Error" return value of IPwatchD internal functions
#define IPWDGN_RV_ERROR   2


/* Structures for D-BUS information  */

//! Structure that holds information about ONE D-BUS bus
typedef struct
{
	char * username;	/**< Username of bus owner */
	uid_t uid;		/**< UID of bus owner */
	char * dbus_address;	/**< Bus address */
}
IPWDGN_S_BUS;

//! Structure that holds information about ALL found D-BUS buses
typedef struct
{
	IPWDGN_S_BUS * bus;	/**< Dynamicaly allocated array of IPWDGN_S_BUS structures */
	int bus_count;		/**< Number of found buses */
}
IPWDGN_S_BUSES;


/* IPwatchD G Notify internal functions */

// \cond - Doxygen ignore block start

void ipwdgn_print_help ();
void ipwdgn_send_desktop_notification (char * program, char * title, char * message);
int ipwdgn_read_file (const char * filename, char ** content);
int ipwdgn_bus_entry_exists (const char * username, const char * dbus_address);
int ipwdgn_create_bus_entry (const char * username, const char * dbus_address);
int ipwdgn_find_buses (void);
void ipwdgn_free_buses (void);
void ipwdgn_debugmsg (const char * message);

// \endcond - Doxygen ignore block end
