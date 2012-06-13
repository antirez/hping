/* 
 * $smu-mark$ 
 * $name: statistics.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:50 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: statistics.c,v 1.3 2004/04/09 23:38:56 antirez Exp $ */

#include <stdlib.h>
#include <stdio.h>

#include "hping2.h"
#include "globals.h"

void	print_statistics(int signal_id)
{
	unsigned int lossrate;

	close_pcap();
	if (recv_pkt > 0)
		lossrate = 100 - ((recv_pkt*100)/sent_pkt);
	else
		if (!sent_pkt)
			lossrate = 0;
		else
			lossrate = 100;

	fprintf(stderr, "\n--- %s hping statistic ---\n", targetname);
	fprintf(stderr, "%d packets tramitted, %d packets received, "
			"%d%% packet loss\n", sent_pkt, recv_pkt, lossrate);
	if (out_of_sequence_pkt)
		fprintf(stderr, "%d out of sequence packets received\n",
			out_of_sequence_pkt);
	fprintf(stderr, "round-trip min/avg/max = %.1f/%.1f/%.1f ms\n",
		rtt_min, rtt_avg, rtt_max);

	/* manage exit code */
	if (opt_tcpexitcode)
	{
		exit(tcp_exitcode);
	}
	else
	{
		if (recv_pkt)
			exit(0);
		else
			exit(1);
	}
};
