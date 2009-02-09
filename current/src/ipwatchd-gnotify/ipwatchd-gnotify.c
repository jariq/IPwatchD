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

/** \file ipwatchd-gnotify.c
 * \brief Standalone notification tool for Gnome environment 
 */


#include "ipwatchd-gnotify.h"


//! Flag indicating debug mode
int debug_flag = 0;

//! Flag indicating broadcast mode
int broadcast_flag = 0;

//! Structure that holds information about available D-BUS buses
IPWDGN_S_BUSES buses;

//! Buffer for debug messages
char msgbuf[IPWDGN_MSG_BUFSIZ];


//! Main function of the ipwatchd-gnotify program
/*!
 * \param argc Number of received command line arguments
 * \param argv Argument values
 * \return 0 if successful
 */
int main (int argc, char *argv[])
{
	char * message = NULL;
	char * title = NULL;
	int c = '?';
	int option_index = 0;

	/* Parse command line arguments */
	while (1)
        {
		static struct option long_options[] = {
			{ "message", required_argument, 0, 'm' },
			{ "title", required_argument, 0, 't' },
			{ "broadcast", no_argument, &broadcast_flag, 1 },
			{ "debug", no_argument, &debug_flag, 1 },
			{ "help", no_argument, 0, 'h' },
			{ "version", no_argument, 0, 'v' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long (argc, argv, "m:t:bdhv", long_options, &option_index);

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

			case 'm':
				if ((message = (char *) malloc ((strlen (optarg) + 1) * sizeof (char))) == NULL)
				{
					printf ("Error: Unable to store message in memory\n");
					return (IPWDGN_RV_ERROR);
				}

				strcpy (message, optarg);
				break;

			case 't':
				if ((title = (char *) malloc ((strlen (optarg) + 1) * sizeof (char))) == NULL)
				{
					printf ("Error: Unable to store message title in memory\n");
					return (IPWDGN_RV_ERROR);
				}

				strcpy (title, optarg);
				break;

			case 'b':
				broadcast_flag = 1;
				break;

			case 'd':
				debug_flag = 1;
				break;

			case 'h':
				ipwdgn_print_help ();
				return (IPWDGN_RV_SUCCESS);

			case 'v':
				printf ("%s\n", IPWATCHD_GNOTIFY_VERSION);
				return (IPWDGN_RV_SUCCESS);

			case '?':
				ipwdgn_print_help ();
				return (IPWDGN_RV_ERROR);

			default:
				ipwdgn_print_help ();
				return (IPWDGN_RV_ERROR);
		}

	}

	/* Print help if there is any unknown argument */
	if (optind < argc)
	{
		ipwdgn_print_help ();
		return (IPWDGN_RV_ERROR);
	}

	/* Message and title must be specified */
	if ((message == NULL) || (title == NULL))
	{
		printf ("Error: You must specify message content and title.\n\n");
		ipwdgn_print_help ();
		return (IPWDGN_RV_ERROR);
	}

	/* Only root can broadcast message */
	if ((broadcast_flag == 1) && (getuid () != 0))
	{
		printf ("Error: You must be root to broadcast a message\n");
		return (IPWDGN_RV_ERROR);
	}

	if (broadcast_flag == 0)
	{
		// Show notification bubble via active notfication daemon
		NotifyNotification * notify = NULL;
		
		if (!notify_init ("IPWATCHD-GNOTIFY"))
		{
			return (IPWDGN_RV_ERROR);
		}
		
		notify = notify_notification_new (title, message, GTK_STOCK_DIALOG_WARNING, NULL);
		notify_notification_set_urgency (notify, NOTIFY_URGENCY_CRITICAL);
		notify_notification_set_timeout (notify, NOTIFY_EXPIRES_DEFAULT);
		notify_notification_show (notify, NULL);
		g_object_unref (G_OBJECT (notify));
		notify_uninit ();
	}
	else
	{
		// Discover all D-BUS buses
		ipwdgn_send_desktop_notification (argv[0], title, message);
	}

	return (IPWDGN_RV_SUCCESS);
}


//! Prints help to stdout
void ipwdgn_print_help ()
{
	printf ("IPwatchD G Notify - Notification tool for Gnome environment\n");
	printf ("\n");
	printf ("Usage: ipwatchd-gnotify [--debug] [--broadcast] --title message_title --message message_content\n");
	printf ("\n");
	printf ("  --debug                    - display debugging information\n");
	printf ("  --broadcast                - send notification to all active displays\n");
	printf ("  --title message_title      - specifies message title\n");
	printf ("  --message message_content  - specifies message content\n");
	printf ("\n");
	printf ("or     ipwatchd-gnotify --version|--help\n");
	printf ("\n");
	printf ("  --version                  - display program version\n");
	printf ("  --help                     - display this help message\n");
	printf ("\n");
	printf ("IPwatchD G Notify is part of IPwatchD project - http://ipwatchd.sf.net/\n");
	printf ("\n");
	printf ("Please send any bug reports to jariq@jariq.sk\n");
}


//! Runs ipwatchd-gnotify in non-broadcast mode for all D_BUS buses
/*!
 * Not very clean solution but it works and we have to stick to it until libnotify will be able to broadcast messages through the system bus.
 * \param program Path to ipwatchd-gnotify executable
 * \param title Title of notification window
 * \param message Message to be shown in notification window  
 */
void ipwdgn_send_desktop_notification (char * program, char * title, char * message)
{
	buses.bus = NULL;
	buses.bus_count = 0;
	
	int i = 0;
	int rv = 0;
	char command[IPWDGN_MSG_BUFSIZ];
	int success = 0;

	ipwdgn_debugmsg ("\nSEARCHING FOR D-BUS BUSES:\n");

	if (ipwdgn_find_buses () == IPWDGN_RV_ERROR)
	{
		printf ("Error: Unable to finish D-BUS buses discovery\n");
		return;
	}

	ipwdgn_debugmsg ("\nPROCESSING DISCOVERED D-BUS BUSES:\n");

	// Loop through all found buses
	for (i = 0; i < buses.bus_count; i++)	
	{
		snprintf (msgbuf, IPWDGN_MSG_BUFSIZ, "\n  D-BUS n.%d:\n", i);
		ipwdgn_debugmsg (msgbuf);

		// Change the DBUS_SESSION_BUS_ADDRESS environment variable
		if (putenv(buses.bus[i].dbus_address) != 0)
		{
			printf ("Error: Unable to set ENVVAR %s\n", buses.bus[i].dbus_address);
			continue;
		}
		else
		{
			snprintf (msgbuf, IPWDGN_MSG_BUFSIZ, "    Set ENVVAR %s\n", buses.bus[i].dbus_address);
			ipwdgn_debugmsg (msgbuf);
		}

		// Change effective user
		if (seteuid (buses.bus[i].uid) != 0)
		{
			printf ("Error: Unable to set EUID %d\n", buses.bus[i].uid);
			continue;
		}
		else
		{
			snprintf (msgbuf, IPWDGN_MSG_BUFSIZ, "    Set EUID %d of user %s\n", buses.bus[i].uid, buses.bus[i].username);
			ipwdgn_debugmsg (msgbuf);
		}

		// Send notification
		snprintf(command, IPWDGN_MSG_BUFSIZ, "%s -t \"%s\" -m \"%s\"", program, title, message);

		rv = system (command);
		if (WIFEXITED(rv))
		{
			rv = WEXITSTATUS(rv);
		}

		if (rv == 0)
		{
			success = success + 1;
			ipwdgn_debugmsg ("    Desktop notification successfuly sent\n");
		}
		else
		{
			printf ("Error: Unable to execute command %s\n", command);
		}

		// Restore root privileges
		if (seteuid (0) != 0)
		{
			printf ("Error: Unable to restore root privileges\n");
			continue;
		}
		else
		{
			ipwdgn_debugmsg ("    Root privileges restored\n");
		}
	}

	snprintf (msgbuf, IPWDGN_MSG_BUFSIZ, "\nNotification successfuly sent to %d of %d buses.\n", success, buses.bus_count);
	ipwdgn_debugmsg (msgbuf);

	ipwdgn_free_buses ();
}


//! Reads content of file into memory buffer
/*!
 * \param filename Name of the file
 * \param content Address of memory buffer
 * \return IPWDGN_RV_SUCCESS if successful IPWDGN_RV_ERROR otherwise
 */
int ipwdgn_read_file (const char * filename, char ** content)
{
	// File descriptor
	int fd = 0;

	// Read length - number of bytes read from file
	size_t rl = 0;

	// Buffer
	char b[IPWDGN_FILE_BUFSIZ];

	// Content of the file
	char *c = NULL;

	// Content length
	int cl = 0;

	if (*content != NULL)
	{
		return IPWDGN_RV_ERROR;
	}

	fd = open (filename, O_RDONLY);
	if (fd == -1)
	{
		return IPWDGN_RV_ERROR;
	}
	
	rl = read (fd, b, IPWDGN_FILE_BUFSIZ);

	while (rl > 0 )
	{
		if ((c = (char *) realloc(c, cl + rl)) == NULL)
		{
			return IPWDGN_RV_ERROR;
		}

		memcpy (c + cl, b, rl);

		cl = cl + rl;

		rl = read (fd, b, IPWDGN_FILE_BUFSIZ);
	}

	if (close (fd) != 0)
	{
		return IPWDGN_RV_ERROR;
	}

	*content = c;

	return cl;
}


//! Searches in buses structure for specific bus
/*!
 * \param username Username of bus owner
 * \param dbus_address Address of bus
 * \return IPWDGN_RV_SUCCESS if bus is found IPWDGN_RV_ERROR otherwise
 */
int ipwdgn_bus_entry_exists (const char * username, const char * dbus_address)
{
	int i = 0;

	for (i = 0; i < buses.bus_count; i++)	
	{
		if ((strcmp (buses.bus[i].username, username) == 0) && (strcmp (buses.bus[i].dbus_address, dbus_address) == 0))
		{
			return IPWDGN_RV_SUCCESS;
		}
	}

	return IPWDGN_RV_ERROR;
}


//! Creates new entry in buses structure
/*!
 * \param username Username of bus owner
 * \param dbus_address Address of bus
 * \return IPWDGN_RV_SUCCESS if successful IPWDGN_RV_ERROR otherwise
 */
int ipwdgn_create_bus_entry (const char * username, const char * dbus_address)
{
	struct passwd * p = NULL;

	// Get user info
	p = getpwnam (username);
	if (p == NULL)
	{
		return IPWDGN_RV_ERROR;
	}

	// Check if entry with same data already exists
	if (ipwdgn_bus_entry_exists (username, dbus_address) == IPWDGN_RV_SUCCESS)
	{
		return IPWDGN_RV_SUCCESS;
	}

	// Allocate memory for new entry in buses structure
	if ((buses.bus = (IPWDGN_S_BUS *) realloc (buses.bus, (buses.bus_count + 1) * sizeof (IPWDGN_S_BUS))) == NULL)
	{
		return IPWDGN_RV_ERROR;
	}

	buses.bus[buses.bus_count].username = NULL;
	buses.bus[buses.bus_count].dbus_address = NULL;

	// Copy username
	if ((buses.bus[buses.bus_count].username  = (char *) malloc ((strlen (username) + 1) * sizeof (char))) == NULL)
	{
		return IPWDGN_RV_ERROR;
	}

	strcpy (buses.bus[buses.bus_count].username, username);

	// Copy UID
	buses.bus[buses.bus_count].uid = p->pw_uid;	

	// Copy DBUS_SESSION_BUS_ADDRESS envvar
	if ((buses.bus[buses.bus_count].dbus_address  = (char *) malloc ((strlen (dbus_address) + 1) * sizeof (char))) == NULL)
	{
		return IPWDGN_RV_ERROR;
	}

	strcpy (buses.bus[buses.bus_count].dbus_address, dbus_address);

	// Increase bus_count
	buses.bus_count = buses.bus_count + 1;

	// Show bus info in debug mode
	ipwdgn_debugmsg ("\n  Discovered bus:\n");
	
	snprintf (msgbuf, IPWDGN_MSG_BUFSIZ, "    User %s UID %d\n", username, p->pw_uid);
	ipwdgn_debugmsg (msgbuf);
	
	snprintf (msgbuf, IPWDGN_MSG_BUFSIZ, "    %s\n", dbus_address);
	ipwdgn_debugmsg (msgbuf);

	return IPWDGN_RV_SUCCESS;
}


//! Searches for D-BUS buses in environment of running processes
/*!
 * \return IPWDGN_RV_SUCCESS if successful IPWDGN_RV_ERROR otherwise
 */
int ipwdgn_find_buses (void)
{
	DIR * dir = NULL;
	struct dirent * dir_entry = NULL;

	char filename[PATH_MAX];
	char * fcontent = NULL;
	unsigned int fcontent_len = 0;

	int i = 0;
	char c = '\0';

	char * bus_search = "DBUS_SESSION_BUS_ADDRESS=";
	int bus_search_len = strlen (bus_search);
	char * bus_result = NULL;

	char * user_search = "USER=";
	int user_search_len = strlen (user_search);
	char * user_result = NULL;
	
	dir = opendir ("/proc/");
	if (dir == NULL)
	{
		return IPWDGN_RV_ERROR;
	}

	while ((dir_entry = readdir (dir)) != NULL)
	{
		// We are interested only in directories ..
		if (dir_entry->d_type != DT_DIR)
		{
			continue;
		}

		// .. and only in PID directories
		if (atoi (dir_entry->d_name) < 1)
		{
			continue;
		}

		snprintf (filename, PATH_MAX, "/proc/%s/environ", dir_entry->d_name);

		// Read environment of the process
		if ((fcontent_len = ipwdgn_read_file (filename, &fcontent)) == 0)
		{
			continue;
		}

		// Search for needed variables
		for (i = 0; i < fcontent_len; i++)
		{
			c = *(fcontent + i);

			// Buffer overflow protection
			if ((i >= (fcontent_len - bus_search_len) ) || (i >= fcontent_len - user_search_len))
			{
				break;
			}

			// Search for DBUS_SESSION_BUS_ADDRESS variable
			if (c == 'D')
			{
				if (memcmp (fcontent + i, bus_search, bus_search_len) == 0)
				{	
					bus_result = (char *) malloc ((strlen (fcontent + i) + 1) * sizeof (char) );
					if (bus_result != NULL)
					{
						strcpy (bus_result, fcontent + i);
					}
				}
			}

			// Search for USER variable
			if (c == 'U')
			{
				if (memcmp (fcontent + i, user_search, user_search_len) == 0)
				{
					user_result = (char *) malloc ((strlen (fcontent + i + user_search_len) +  1) * sizeof (char) );
					if (user_result != NULL)
					{
						strcpy (user_result, fcontent + i + user_search_len);
					}
				}
			}

		}

		// Create new bus entry in buses structure if all needed data found 
		if ((bus_result != NULL) && (user_result != NULL))
		{
			ipwdgn_create_bus_entry (user_result, bus_result);
		}

		// Free memory
		if (bus_result != NULL)
		{
			free (bus_result);
			bus_result = NULL;
		}
		
		if (user_result != NULL)
		{
			free (user_result);
			user_result = NULL;
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
		return IPWDGN_RV_ERROR;
	}

	return IPWDGN_RV_SUCCESS;
}


//! Removes all entries from buses structre
void ipwdgn_free_buses (void)
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


//! Prints debug message to stdout
/*
 * /param message Debug message
 */
void ipwdgn_debugmsg (const char * message)
{
	if (debug_flag)
	{
		printf ("%s", message);
	}
}
