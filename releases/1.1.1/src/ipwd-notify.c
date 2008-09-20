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

/** \file ipwd-notify.c
 * \brief Standalone program used for sending desktop notifications
 */


#include <stdio.h>
#include <libnotify/notify.h>


//! Main function of the ipwd-notify program
/*!
 * \param argc Number of received command line arguments
 * \param argv Argument values
 * \return 0 if successful 1 otherwise
 */
int main (int argc, char *argv[])
{
	if (argc < 2)
	{
		printf ("Usage: ipwd-notify message\n");
		return 1;
	}

	NotifyNotification *notify = NULL;

	if (!notify_init("IPwatchD"))
	{
		return 1;
	}

	notify = notify_notification_new("IP Conflict occured", argv[1], GTK_STOCK_DIALOG_WARNING, NULL);
	notify_notification_set_urgency(notify, NOTIFY_URGENCY_CRITICAL);
	notify_notification_set_timeout(notify, NOTIFY_EXPIRES_DEFAULT);
	notify_notification_show(notify, NULL);
	g_object_unref(G_OBJECT(notify));
	notify_uninit();

	return 0;
}

