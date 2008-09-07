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

/** \file desktop.c
 * \brief Contains logic used for showing notification pop-ups on desktop
 */


#include "ipwatchd.h"


extern IPWD_S_BUSES buses;
extern char msgbuf[IPWD_MSG_BUFSIZ];


//! Shows desktop pop-up notification with libnotify
/*!
 * Not very clean solution but it works and we have to stick to it until libnotify will be able to broadcast messages through the system bus.
 * \param message Message to be shown
 */
void ipwd_send_desktop_notification (char *message)
{
	buses.bus = NULL;
	buses.bus_count = 0;
	int i = 0;
	char command[IPWD_MSG_BUFSIZ];
	int rv = 0;

	if (ipwd_find_buses () == IPWD_RV_ERROR)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Error occurred while searching for available buses");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return;
	}

	// Loop through all found buses
	for (i = 0; i < buses.bus_count; i++)	
	{
		// Change environment variable with D-BUS bus address
		if (putenv(buses.bus[i].dbus_address) != 0)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to set environment variable %s", buses.bus[i].dbus_address);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			continue;
		}

		// Change effective user
		if (seteuid (buses.bus[i].uid) != 0)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to set effective uid to %d", buses.bus[i].uid);
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			continue;
		}

		// Send notification
		snprintf(command, IPWD_MSG_BUFSIZ, "/usr/local/sbin/ipwd-notify \"%s\"", message);

		rv = system(command);
		if (WIFEXITED(rv))
		{
			rv = WEXITSTATUS(rv);
		}

		if (rv != 0) {
			// TODO
			// Need to rewrite logic and add something like statistics
			// i.e. notification sent successfuly to 4 out of 10 buses
		}

		// Restore root privileges
		if (seteuid(0) != 0)
		{
			snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to restore root privileges");
			ipwd_message (msgbuf, IPWD_MSG_ERROR);
			continue;
		}
		
	}
	
	ipwd_free_buses ();
	
}


//! Reads content of file into memory buffer
/*!
 * \param filename Name of the file
 * \param content Address of memory buffer
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_read_file (const char *filename, char **content)
{
	// File descriptor
	int fd = 0;
	// Read length - number of bytes read from file
	size_t rl = 0;
	// Buffer
	char b[IPWD_FILE_BUFSIZ];
	// Content of the file
	char *c = NULL;
	// Content length
	int cl = 0;

	if (*content != NULL)
	{
		return IPWD_RV_ERROR;
	}

	fd = open (filename, O_RDONLY);
	if (fd == -1)
	{
		return IPWD_RV_ERROR;
	}
	
	rl = read (fd, b, IPWD_FILE_BUFSIZ);

	while (rl > 0 )
	{
		if ((c = (char *) realloc(c, cl + rl)) == NULL)
		{
			return IPWD_RV_ERROR;
		}

		memcpy (c + cl, b, rl);

		cl = cl + rl;

		rl = read (fd, b, IPWD_FILE_BUFSIZ);
	}

	if (close (fd) != 0)
	{
		return IPWD_RV_ERROR;
	}

	*content = c;

	return cl;
}


//! Searches in buses structure for specific bus
/*!
 * \param username Username of bus owner
 * \param dbus_address Address of bus
 * \return IPWD_RV_SUCCESS if bus is found IPWD_RV_ERROR otherwise
 */
int ipwd_bus_entry_exists (const char *username, const char *dbus_address)
{
	int i = 0;

	for (i = 0; i < buses.bus_count; i++)	
	{
		if ((strcmp (buses.bus[i].username, username) == 0) && (strcmp (buses.bus[i].dbus_address, dbus_address) == 0))
		{
			return IPWD_RV_SUCCESS;
		}
	}

	return IPWD_RV_ERROR;
}


//! Creates new entry in buses structure
/*!
 * \param username Username of bus owner
 * \param dbus_address Address of bus
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_create_bus_entry (const char *username, const char *dbus_address)
{
	struct passwd *p = NULL;

	// Get user info
	p = getpwnam(username);
	if (p == NULL)
	{
		return IPWD_RV_ERROR;
	}

	// Check if entry with same data already exists
	if (ipwd_bus_entry_exists(username, dbus_address) == IPWD_RV_SUCCESS)
	{
		return IPWD_RV_SUCCESS;
	}

	// Allocate memory for new entry in buses structure
	if ((buses.bus = (IPWD_S_BUS *) realloc (buses.bus, (buses.bus_count + 1) * sizeof (IPWD_S_BUS))) == NULL)
	{
		return IPWD_RV_ERROR;
	}

	buses.bus[buses.bus_count].username = NULL;
	buses.bus[buses.bus_count].dbus_address = NULL;

	// username
	if ((buses.bus[buses.bus_count].username  = (char *) malloc ( (strlen (username) + 1) * sizeof (char))) == NULL)
	{
		return IPWD_RV_ERROR;
	}

	strcpy (buses.bus[buses.bus_count].username, username);

	// uid
	buses.bus[buses.bus_count].uid = p->pw_uid;	

	// dbus_address
	if ((buses.bus[buses.bus_count].dbus_address  = (char *) malloc ( (strlen (dbus_address) + 1) * sizeof (char))) == NULL)
	{
		return IPWD_RV_ERROR;
	}

	strcpy (buses.bus[buses.bus_count].dbus_address, dbus_address);

	// Increase bus_count
	buses.bus_count = buses.bus_count + 1;

	return IPWD_RV_SUCCESS;
}


//! Searches for available buses in /proc
/*!
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_find_buses (void)
{
	DIR *dir = NULL;
	struct dirent *dir_entry = NULL;

	char filename[PATH_MAX];
	char *fcontent = NULL;
	unsigned int fcontent_len = 0;

	int i = 0;
	char c = '\0';

	char *search1 = "DBUS_SESSION_BUS_ADDRESS=";
	int search1len = strlen (search1);
	char *search1result = NULL;

	char *search2 = "USER=";
	int search2len = strlen (search2);
	char *search2result = NULL;
	
	dir = opendir ("/proc/");
	if (dir == NULL)
	{
		return IPWD_RV_ERROR;
	}

	while ((dir_entry = readdir (dir)) != NULL)
	{
		// We are intereste only in directories ..
		if (dir_entry->d_type != DT_DIR)
		{
			continue;
		}

		// .. and only in PID directories
		if (atoi (dir_entry->d_name) < 1)
		{
			continue;
		}

		snprintf(filename, PATH_MAX, "/proc/%s/environ", dir_entry->d_name);

		// Read environment of the process
		if ((fcontent_len = ipwd_read_file (filename, &fcontent)) == 0)
		{
			continue;
		}

		// Search for needed variables
		for (i = 0; i < fcontent_len; i++)
		{
			c = *(fcontent + i);

			// Buffer overflow protection
			if ((i >= (fcontent_len - search1len) ) || (i >= fcontent_len - search2len))
			{
				break;
			}

			// Search for DBUS_SESSION_BUS_ADDRESS variable
			if (c == 'D')
			{
				if (memcmp (fcontent + i, search1, search1len) == 0)
				{	
					search1result = (char *) malloc( (strlen (fcontent + i) + 1) * sizeof (char) );
					if (search1result != NULL)
					{
						strcpy(search1result, fcontent + i);
					}
				}
			}

			// Search for USER variable
			if (c == 'U')
			{
				if (memcmp (fcontent + i, search2, search2len) == 0)
				{
					search2result = (char *) malloc( (strlen (fcontent + i + search2len) +  1) * sizeof (char) );
					if (search2result != NULL)
					{
						strcpy(search2result, fcontent + i + search2len);
					}
				}
			}

		}

		// Create new bus entry in buses structure if all needed data found 
		if ((search1result != NULL) && (search2result != NULL))
		{
			ipwd_create_bus_entry (search2result, search1result);
		}

		// Free memory
		if (search1result != NULL)
		{
			free (search1result);
			search1result = NULL;
		}
		
		if (search2result != NULL)
		{
			free (search2result);
			search2result = NULL;
		}

		if (fcontent != NULL)
		{
			free (fcontent);
			fcontent = NULL;
			fcontent_len = 0;
		}
	}

	if (closedir (dir) != 0)
	{
		return IPWD_RV_ERROR;
	}

	return IPWD_RV_SUCCESS;
}


//! Removes all entries from buses structre
void ipwd_free_buses (void)
{
	int i = 0;

	for (i = 0; i < buses.bus_count; i++)	
	{
		if (buses.bus[i].username != NULL)
		{
			free (buses.bus[i].username);
			buses.bus[i].username = NULL;
		}

		if (buses.bus[i].dbus_address != NULL)
		{
			free (buses.bus[i].dbus_address);
			buses.bus[i].dbus_address = NULL;
		}
	}

	if (buses.bus != NULL)
	{
		free (buses.bus);
		buses.bus = NULL;
		buses.bus_count = 0;
	}
}

