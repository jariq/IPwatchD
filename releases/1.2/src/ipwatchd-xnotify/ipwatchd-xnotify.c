/* IPwatchD X Notify - Notification tool for X window environment
 * Copyright (C) 2009-2010 Jaroslav Imrich <jariq(at)jariq(dot)sk>
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

/** \file ipwatchd-xnotify.c
 * \brief Standalone notification tool for X window environment
*/


#include "ipwatchd-xnotify.h"


//! Flag indicating debug mode
int debug_flag = 0;

//! Flag indicating broadcast mode
int broadcast_flag = 0;

//! Structure that holds information about available X diplays
IPWDXN_S_DISPLAYS displays;

//! Buffer for debug messages
char msgbuf[IPWDXN_MSG_BUFSIZ];


//! Main function of the ipwatchd-xnotify program
/*!
 * \param argc Number of received command line arguments
 * \param argv Argument values
 * \return 0 if successful
 */
int main (int argc, char * argv[])
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
					return (IPWDXN_RV_ERROR);
				}

				strcpy (message, optarg);
				break;

			case 't':
				if ((title = (char *) malloc ((strlen (optarg) + 1) * sizeof (char))) == NULL)
				{
					printf ("Error: Unable to store message title in memory\n");
					return (IPWDXN_RV_ERROR);
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
				ipwdxn_print_help ();
				return (IPWDXN_RV_SUCCESS);

			case 'v':
				printf ("%s\n", IPWATCHD_XNOTIFY_VERSION);
				return (IPWDXN_RV_SUCCESS);

			case '?':
				ipwdxn_print_help ();
				return (IPWDXN_RV_ERROR);

			default:
				ipwdxn_print_help ();
				return (IPWDXN_RV_ERROR);
		}

	}

	/* Print help if there is any unknown argument */
	if (optind < argc)
	{
		ipwdxn_print_help ();
		return (IPWDXN_RV_ERROR);
	}

	/* Message and title must be specified */
	if ((message == NULL) || (title == NULL))
	{
		printf ("Error: You must specify message content and title.\n\n");
		ipwdxn_print_help();
		return (IPWDXN_RV_ERROR);
	}

	/* Only root can broadcast message */
	if ((broadcast_flag == 1) && (getuid () != 0))
	{
		printf ("Error: You must be root to broadcast a message\n");
		return (IPWDXN_RV_ERROR);
	}

	if (broadcast_flag == 0)
	{
		// Show GTK dialog with warning icon on active X display
		GtkWidget *dialog = NULL;
		gtk_init (&argc, &argv);
		dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, "%s", message);
		gtk_window_set_title (GTK_WINDOW (dialog), title);
		gtk_window_set_keep_above (GTK_WINDOW (dialog), TRUE);
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
	}
	else
	{
		// Discover all X displays
		ipwdxn_send_desktop_notification (argv[0], title, message);
	}

	return (IPWDXN_RV_SUCCESS);
}


//! Prints help to stdout
void ipwdxn_print_help ()
{
	printf ("IPwatchD X Notify - Notification tool for X window environment\n");
	printf ("\n");
    	printf ("Usage: ipwatchd-xnotify [--debug] [--broadcast] --title message_title --message message_content\n");
	printf ("\n");
	printf ("  --debug                    - display debugging information\n");
	printf ("  --broadcast                - send notification to all active displays\n");
	printf ("  --title message_title      - specifies message title\n");
	printf ("  --message message_content  - specifies message content\n");
	printf ("\n");
    	printf ("or     ipwatchd-xnotify --version|--help\n");
	printf ("\n");
	printf ("  --version                  - display program version\n");
	printf ("  --help                     - display this help message\n");
	printf ("\n");
	printf ("IPwatchD X Notify is part of IPwatchD project - http://ipwatchd.sf.net/\n");
	printf ("\n");
	printf ("Please send any bug reports to jariq@jariq.sk\n");
}


//! Runs ipwatchd-xnotify in non-broadcast mode for all X displays
/*
 * \param program Path to ipwatchd-xnotify executable
 * \param title Title of dialog window
 * \param message Message to be shown in dialog window
 */
void ipwdxn_send_desktop_notification (char * program, char * title, char * message)
{
	displays.display = NULL;
	displays.display_count = 0;

	int i = 0;
	int rv = 0;
	char command[IPWDXN_MSG_BUFSIZ];

	ipwdxn_debugmsg ("\nSEARCHING FOR X DISPLAYS:\n");

	if (ipwdxn_find_displays () == IPWDXN_RV_ERROR)
	{
		printf ("Error: Unable to finish X display discovery\n");
		return;
	}

	ipwdxn_debugmsg ("\nPROCESSING DISCOVERED X DISPLAYS:\n");

	// Loop through all found displays
	for (i = 0; i < displays.display_count; i++)	
	{
		snprintf (msgbuf, IPWDXN_MSG_BUFSIZ, "\n  Display n.%d:\n", i);
		ipwdxn_debugmsg (msgbuf);

		// Change the DISPLAY environment variable
		if (putenv(displays.display[i].display) != 0)
		{
			printf ("Error: Unable to set ENVVAR %s\n", displays.display[i].display);
			continue;
		}
		else
		{
			snprintf (msgbuf, IPWDXN_MSG_BUFSIZ, "    Set ENVVAR %s\n", displays.display[i].display);
			ipwdxn_debugmsg (msgbuf);
		}

		// Change the XAUTHORITY environment variable
		if (putenv(displays.display[i].xauthority) != 0)
		{
			printf ("Error: Unable to set ENVVAR %s\n", displays.display[i].xauthority);
			continue;
		}
		else
		{
			snprintf (msgbuf, IPWDXN_MSG_BUFSIZ, "    Set ENVVAR %s\n", displays.display[i].xauthority);
			ipwdxn_debugmsg (msgbuf);
		}

		// Change effective user
		if (seteuid (displays.display[i].uid) != 0)
		{
			printf ("Error: Unable to set EUID %d\n", displays.display[i].uid);
			continue;
		}
		else
		{
			snprintf (msgbuf, IPWDXN_MSG_BUFSIZ, "    Set EUID %d of user %s\n", displays.display[i].uid, displays.display[i].username);
			ipwdxn_debugmsg (msgbuf);
		}

		// Send notification
		snprintf (command, IPWDXN_MSG_BUFSIZ, "%s -t \"%s\" -m \"%s\" &", program, title, message);

		snprintf (msgbuf, IPWDXN_MSG_BUFSIZ, "    Executing %s\n", command);
		ipwdxn_debugmsg (msgbuf);

		rv = system(command);
		if (rv == -1)
		{
			printf ("Error: Unable to execute command %s\n", command);
		}

		// Restore root privileges
		if (seteuid(0) != 0)
		{
			printf ("Error: Unable to restore root privileges\n");
			continue;
		}
		else
		{
			ipwdxn_debugmsg ("    Root privileges restored\n");
		}
	}

	ipwdxn_debugmsg ("\nAll displays processed.\n");

	ipwdxn_free_displays ();
}


//! Reads content of file into memory buffer
/*!
 * \param filename Name of the file
 * \param content Address of memory buffer
 * \return IPWDXN_RV_SUCCESS if successful IPWDXN_RV_ERROR otherwise
 */
int ipwdxn_read_file (const char *filename, char **content)
{
	// File descriptor
	int fd = 0;

	// Read length - number of bytes read from file
	size_t rl = 0;

	// Buffer
	char b[IPWDXN_FILE_BUFSIZ];

	// Content of the file
	char *c = NULL;

	// Content length
	int cl = 0;

	if (*content != NULL)
	{
		return IPWDXN_RV_ERROR;
	}

	fd = open (filename, O_RDONLY);
	if (fd == -1)
	{
		return IPWDXN_RV_ERROR;
	}
	
	rl = read (fd, b, IPWDXN_FILE_BUFSIZ);

	while (rl > 0 )
	{
		if ((c = (char *) realloc(c, cl + rl)) == NULL)
		{
			return IPWDXN_RV_ERROR;
		}

		memcpy (c + cl, b, rl);

		cl = cl + rl;

		rl = read (fd, b, IPWDXN_FILE_BUFSIZ);
	}

	if (close (fd) != 0)
	{
		return IPWDXN_RV_ERROR;
	}

	*content = c;

	return cl;
}


//! Searches in displays structure for specific display
/*!
 * \param display DISPLAY environment variable
 * \return IPWDXN_RV_SUCCESS if display is found IPWDXN_RV_ERROR otherwise
 */
int ipwdxn_display_entry_exists (const char *display)
{
	int i = 0;

	for (i = 0; i < displays.display_count; i++)	
	{
		// Handles :0.0 as :0 as the same display
		if (strncmp (displays.display[i].display, display, 10) == 0)
		{
			return IPWDXN_RV_SUCCESS;
		}
	}

	return IPWDXN_RV_ERROR;
}


//! Creates new entry in displays structure
/*!
 * \param username Username of display owner
 * \param display DISPLAY environment variable
 * \param xauthority XAUTHORITY environment variable
 * \return IPWDXN_RV_SUCCESS if successful IPWDXN_RV_ERROR otherwise
 */
int ipwdxn_create_display_entry (const char *username, const char *display, const char *xauthority)
{
	struct passwd *p = NULL;

	// Get user info
	p = getpwnam(username);
	if (p == NULL)
	{
		return IPWDXN_RV_ERROR;
	}

	// Check if entry for this display allready exists
	if (ipwdxn_display_entry_exists (display) == IPWDXN_RV_SUCCESS)
	{
		return IPWDXN_RV_SUCCESS;
	}

	// Allocate memory for new entry in displays structure
	if ((displays.display = (IPWDXN_S_DISPLAY *) realloc (displays.display, (displays.display_count + 1) * sizeof (IPWDXN_S_DISPLAY))) == NULL)
	{
		return IPWDXN_RV_ERROR;
	}

	displays.display[displays.display_count].username = NULL;
	displays.display[displays.display_count].display = NULL;
	displays.display[displays.display_count].xauthority = NULL;

	// Copy username
	if ((displays.display[displays.display_count].username  = (char *) malloc ( (strlen (username) + 1) * sizeof (char))) == NULL)
	{
		return IPWDXN_RV_ERROR;
	}

	strcpy (displays.display[displays.display_count].username, username);

	// Copy UID
	displays.display[displays.display_count].uid = p->pw_uid;

	// Copy DISPLAY envvar
	if ((displays.display[displays.display_count].display  = (char *) malloc ( (strlen (display) + 1) * sizeof (char))) == NULL)
	{
		return IPWDXN_RV_ERROR;
	}

	strcpy (displays.display[displays.display_count].display, display);

	// Copy XAUTHORITY envvar
	if ((displays.display[displays.display_count].xauthority  = (char *) malloc ( (strlen (xauthority) + 1) * sizeof (char))) == NULL)
	{
		return IPWDXN_RV_ERROR;
	}

	strcpy (displays.display[displays.display_count].xauthority, xauthority);

	// Increase display_count
	displays.display_count = displays.display_count + 1;

	// Show display info in debug mode
	ipwdxn_debugmsg ("\n  Discovered display:\n");
	
	snprintf (msgbuf, IPWDXN_MSG_BUFSIZ, "    User %s UID %d\n", username, p->pw_uid);
	ipwdxn_debugmsg (msgbuf);
	
	snprintf (msgbuf, IPWDXN_MSG_BUFSIZ, "    %s\n", display);
	ipwdxn_debugmsg (msgbuf);
	
	snprintf (msgbuf, IPWDXN_MSG_BUFSIZ, "    %s\n", xauthority);
	ipwdxn_debugmsg (msgbuf);
	
	return IPWDXN_RV_SUCCESS;
}


//! Searches for X displays in environment of running processes
/*!
 * \return IPWDXN_RV_SUCCESS if successful IPWDXN_RV_ERROR otherwise
 */
int ipwdxn_find_displays (void)
{
	DIR * dir = NULL;
	struct dirent * dir_entry = NULL;

	char filename[PATH_MAX];
	char * fcontent = NULL;
	unsigned int fcontent_len = 0;

	int i = 0;
	char c = '\0';

	char * display_search = "DISPLAY=";
	int display_search_len = strlen (display_search);
	char * display_result = NULL;

	char * user_search = "USER=";
	int user_search_len = strlen (user_search);
	char * user_result = NULL;
	
	char * xauthority_search = "XAUTHORITY=";
	int xauthority_search_len = strlen (xauthority_search);
	char * xauthority_result = NULL;

	dir = opendir ("/proc/");
	if (dir == NULL)
	{
		return IPWDXN_RV_ERROR;
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

		snprintf(filename, PATH_MAX, "/proc/%s/environ", dir_entry->d_name);

		// Read environment of the process
		if ((fcontent_len = ipwdxn_read_file (filename, &fcontent)) == 0)
		{
			continue;
		}

		// Search for needed variables
		for (i = 0; i < fcontent_len; i++)
		{
			c = *(fcontent + i);

			// Buffer overflow protection
			if ((i >= (fcontent_len - display_search_len) ) || (i >= fcontent_len - user_search_len) || (i >= fcontent_len - xauthority_search_len))
			{
				break;
			}

			// Search for DISPLAY variable
			if (c == 'D')
			{
				if (memcmp (fcontent + i, display_search, display_search_len) == 0)
				{	
					display_result = (char *) malloc ((strlen (fcontent + i) + 1) * sizeof (char) );
					if (display_result != NULL)
					{
						strcpy (display_result, fcontent + i);
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

			// Search for XAUTHORITY variable
			if (c == 'X')
			{
				if (memcmp (fcontent + i, xauthority_search, xauthority_search_len) == 0)
				{	
					xauthority_result = (char *) malloc ((strlen (fcontent + i) + 1) * sizeof (char) );
					if (xauthority_result != NULL)
					{
						strcpy (xauthority_result, fcontent + i);
					}
				}
			}
		}

		// Create new display entry in displays structure if all needed data found 
		if ((display_result != NULL) && (user_result != NULL) && (xauthority_result != NULL))
		{
			ipwdxn_create_display_entry (user_result, display_result, xauthority_result);
		}

		// Free memory
		if (display_result != NULL)
		{
			free (display_result);
			display_result = NULL;
		}
		
		if (user_result != NULL)
		{
			free (user_result);
			user_result = NULL;
		}

		if (xauthority_result != NULL)
		{
			free (xauthority_result);
			xauthority_result = NULL;
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
		return IPWDXN_RV_ERROR;
	}

	return IPWDXN_RV_SUCCESS;
}


//! Removes all entries from displays structre
void ipwdxn_free_displays (void)
{
	int i = 0;

	for (i = 0; i < displays.display_count; i++)	
	{
		if (displays.display[i].username != NULL)
		{
			free (displays.display[i].username);
			displays.display[i].username = NULL;
		}

		if (displays.display[i].display != NULL)
		{
			free (displays.display[i].display);
			displays.display[i].display = NULL;
		}

		if (displays.display[i].xauthority != NULL)
		{
			free (displays.display[i].xauthority);
			displays.display[i].xauthority = NULL;
		}
	}

	if (displays.display != NULL)
	{
		free (displays.display);
		displays.display = NULL;
		displays.display_count = 0;
	}
}



//! Prints debug message to stdout
/*
 * /param message Debug message
 */
void ipwdxn_debugmsg (const char * message)
{
	if (debug_flag)
	{
		printf ("%s", message);
	}
}

