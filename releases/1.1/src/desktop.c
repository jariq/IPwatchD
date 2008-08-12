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


#include <libnotify/notify.h>
#include "ipwatchd.h"


//! Shows desktop pop-up notification with libnotify
/*!
 * \param message Message to be shown
 */
void ipwd_desktop_notification(char *message)
{
	NotifyNotification *notify = NULL;

	if (!notify_init("IPwatchD"))
	{
		ipwd_message ("Unable to connect to notification daemon", IPWD_MSG_ERROR);
		return;
	}

	notify = notify_notification_new("IP Conflict occured", message, GTK_STOCK_DIALOG_WARNING, NULL);
	notify_notification_set_urgency(notify, NOTIFY_URGENCY_CRITICAL);
	notify_notification_set_timeout(notify, NOTIFY_EXPIRES_DEFAULT);
	notify_notification_show(notify, NULL);
	g_object_unref(G_OBJECT(notify));
	notify_uninit();
}

