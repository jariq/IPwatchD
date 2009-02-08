/* IPwatchD X Notify - Notification tool for X window environment
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

/** \file ipwatchd-xnotify.h
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
#include <gtk/gtk.h>


//! String with IPwatchD X Notify version information
#define IPWATCHD_XNOTIFY_VERSION "IPwatchD X Notify 1.0"

//! Size of buffer for output messages
#define IPWDXN_MSG_BUFSIZ  1000

//! Size of buffer used for reading content of files
#define IPWDXN_FILE_BUFSIZ 1000


/* Return values */

//! "Success" return value of IPwatchD internal functions
#define IPWDXN_RV_SUCCESS 0

//! "Error" return value of IPwatchD internal functions
#define IPWDXN_RV_ERROR   2


/* Structures for X window display information  */

//! Structure that holds information about ONE x window display
typedef struct
{
	char * username;	/**< Username of display owner */
	uid_t uid;		/**< UID of the display owner */
	char * display;		/**< DISPLAY environment variable */
	char * xauthority;	/**< XAUTHORITY environment variable */
}
IPWDXN_S_DISPLAY;

//! Structure that holds information about ALL x window displays
typedef struct
{
	IPWDXN_S_DISPLAY * display;	/**< Dynamicaly allocated array of IPWDXN_S_DISPLAY structures */
	int display_count;		/**< Number of discovered displays */
}
IPWDXN_S_DISPLAYS;


/* IPwatchD X Notify internal functions */

// \cond - Doxygen ignore block start

void ipwdxn_print_help ();
void ipwdxn_send_desktop_notification (char * program, char * title, char * message);
int ipwdxn_read_file (const char * filename, char ** content);
int ipwdxn_display_entry_exists (const char * display);
int ipwdxn_create_display_entry (const char * username, const char * display, const char * xauthority);
int ipwdxn_find_displays (void);
void ipwdxn_free_displays (void);
void ipwdxn_debugmsg (const char * message);

// \endcond - Doxygen ignore block end

