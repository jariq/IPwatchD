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

/** \file daemonize.c
 * \brief Contains logic used for daemonization of the proccess
 */


#include "ipwatchd.h"


extern char msgbuf[IPWD_MSG_BUFSIZ];


//! Daemonizes the proccess
/*!
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_daemonize (void)
{

	/* If parent of this process is init we are already in daemon mode */
	if (getppid () == 1)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Already running as daemon");
		ipwd_message (msgbuf, IPWD_MSG_INFO);
		return (IPWD_RV_SUCCESS);
	}

	/* Fork child process */
	pid_t pid = fork ();
	if (pid < 0)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to fork a child process");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Fork was successful we can exit parent */
	if (pid > 0)
	{
		exit (IPWD_RV_SUCCESS);
	}

	/* Set default umask */
	umask (0);

	/* Create new session */
	pid_t sid = setsid ();
	if (sid < 0)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to create a new session");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Change current directory to root */
	if ((chdir ("/")) == -1)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to change current directory to /");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Redirect standard input */
	if ((freopen ("/dev/null", "r", stdin)) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to redirect STDIN");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Redirect standard output */
	if ((freopen ("/dev/null", "w", stdout)) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to redirect STDOUT");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	/* Redirect standard error output */
	if ((freopen ("/dev/null", "w", stderr)) == NULL)
	{
		snprintf (msgbuf, IPWD_MSG_BUFSIZ, "Unable to redirect STDERR");
		ipwd_message (msgbuf, IPWD_MSG_ERROR);
		return (IPWD_RV_ERROR);
	}

	return (IPWD_RV_SUCCESS);

}

