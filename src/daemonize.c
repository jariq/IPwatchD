/* IPwatchD - IP conflict detection tool for Linux
 * Copyright (C) 2007-2018 Jaroslav Imrich <jariq(at)jariq(dot)sk>
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


extern int syslog_flag;
extern IPWD_S_CONFIG config;


//! Daemonizes the proccess
/*!
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_daemonize (void)
{

	/* Check if ipwatchd is running - only one daemon instance is allowed */
	if (ipwd_check_pidfile () != IPWD_RV_SUCCESS) 
	{
		return (IPWD_RV_ERROR);
	}

	/* Fork child process */
	pid_t pid = fork ();
	if (pid < 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to fork a child process");
		return (IPWD_RV_ERROR);
	}

	/* Fork was successful we can exit parent */
	if (pid > 0)
	{
		exit (IPWD_RV_SUCCESS);
	}

	/* All messages must be sysloged since now */
	openlog ("ipwatchd", LOG_PID | LOG_CONS | LOG_NDELAY, config.facility);
	syslog_flag = 1;

	/* Set default umask */
	umask (0166);

	/* Create new session */
	pid_t sid = setsid ();
	if (sid < 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to create a new session");
		return (IPWD_RV_ERROR);
	}

	/* Change current directory to root */
	if ((chdir ("/")) == -1)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to change current directory to /");
		return (IPWD_RV_ERROR);
	}

	/* Redirect standard input */
	if ((freopen ("/dev/null", "r", stdin)) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to redirect STDIN");
		return (IPWD_RV_ERROR);
	}

	/* Redirect standard output */
	if ((freopen ("/dev/null", "w", stdout)) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to redirect STDOUT");
		return (IPWD_RV_ERROR);
	}

	/* Redirect standard error output */
	if ((freopen ("/dev/null", "w", stderr)) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to redirect STDERR");
		return (IPWD_RV_ERROR);
	}

	/* Create PID file */
	if (ipwd_create_pidfile () != IPWD_RV_SUCCESS)
	{
		return (IPWD_RV_ERROR);
	}

	return (IPWD_RV_SUCCESS);

}


//! Creates PID file
/*!
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_create_pidfile (void)
{

	FILE * fw = NULL;

	if ((fw = fopen (IPWD_PIDFILE, "w")) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to open PID file %s", IPWD_PIDFILE);
		return (IPWD_RV_ERROR);
	}

	if (fprintf (fw, "%d", getpid()) < 0) {
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to write process PID into PID file %s", IPWD_PIDFILE);
		fclose (fw);
		return (IPWD_RV_ERROR);
	}

	if (fclose (fw) == EOF) {
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to close PID file %s", IPWD_PIDFILE);	
		return (IPWD_RV_ERROR);
	}

	return (IPWD_RV_SUCCESS);

}


//! Checks if process is already running
/*!
 * \return IPWD_RV_SUCCESS if process is not running IPWD_RV_ERROR otherwise
 */
int ipwd_check_pidfile (void)
{

	FILE * fr = NULL;
	char proc_this_lnk[PATH_MAX];
	char proc_this_bin[PATH_MAX];
	int  proc_this_pid = -1;
	char proc_pidfile_lnk[PATH_MAX];
	char proc_pidfile_bin[PATH_MAX];
	int  proc_pidfile_pid = -1;

	/* Fill buffers with nulls */
	memset (proc_this_lnk, '\0', PATH_MAX);
	memset (proc_this_bin, '\0', PATH_MAX);
	memset (proc_pidfile_lnk, '\0', PATH_MAX);
	memset (proc_pidfile_bin, '\0', PATH_MAX);

	/* Determine absolute path of executable for current process */
	proc_this_pid = getpid ();

	snprintf (proc_this_lnk, PATH_MAX, "/proc/%d/exe", proc_this_pid);

	if (readlink (proc_this_lnk, proc_this_bin, PATH_MAX) <= 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to get information about current process");
		return (IPWD_RV_ERROR);
	}
	
	/* Read contents of PID file */
	if ((fr = fopen (IPWD_PIDFILE, "r")) == NULL)
	{
		if (errno == ENOENT)
		{
			ipwd_message (IPWD_MSG_TYPE_DEBUG, "Daemon can be executed because PID file %s does not exist", IPWD_PIDFILE);
			return (IPWD_RV_SUCCESS);
		}

		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to open PID file %s", IPWD_PIDFILE);
		return (IPWD_RV_ERROR);
	}

	if (fscanf (fr, "%d", &proc_pidfile_pid) != 1)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to read PID from PID file %s", IPWD_PIDFILE);
		fclose (fr);
		return (IPWD_RV_ERROR);
	}

	if (fclose (fr) == EOF)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to close PID file %s", IPWD_PIDFILE);
		return (IPWD_RV_ERROR);
	}

	/* Determine absolute path of executable for process specified in PID file */
	snprintf (proc_pidfile_lnk, PATH_MAX, "/proc/%d/exe", proc_pidfile_pid);

	if (readlink (proc_pidfile_lnk, proc_pidfile_bin, PATH_MAX) <= 0)
	{
		if (errno == ENOENT)
		{
			ipwd_message (IPWD_MSG_TYPE_DEBUG, "Daemon can be executed because process specified in PID file %s does not exist", IPWD_PIDFILE);
			return (IPWD_RV_SUCCESS);
		}

		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to get information about process specified in PID file");
		return (IPWD_RV_ERROR);
	}

	/* Compare absolute path of executable for current process with absolute path of executable for process specified in PID file */
	if (strcmp (proc_this_bin, proc_pidfile_bin) == 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "IPwatchD is already running");
		return (IPWD_MSG_TYPE_ERROR);
	}

	// ipwd_message (IPWD_MSG_INFO, "Daemon can be executed because process specified in PID file is not IPwatchD");
	return (IPWD_RV_SUCCESS);

}

