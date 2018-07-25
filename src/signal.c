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

/** \file signal.c
 * \brief Contains logic used for signal handling
 */


#include "ipwatchd.h"


extern pcap_t *h_pcap;


//! Sets signal handler for SIGTERM
/*!
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_set_signal_handler (void)
{

	struct sigaction sigact;

	sigemptyset (&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigact.sa_handler = ipwd_signal_handler;

	if (sigaction (SIGTERM, &sigact, 0) != 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to set SIGTERM handler");
		return (IPWD_RV_ERROR);
	}

	return (IPWD_RV_SUCCESS);

}


//! Signal handler that is called when signal received
/*!
 * \param signal Signal identifier
 */
void ipwd_signal_handler (int signal)
{

	ipwd_message (IPWD_MSG_TYPE_DEBUG, "Received signal %d", signal);

	if (signal == SIGTERM)
	{
		pcap_breakloop (h_pcap);
	}

}

