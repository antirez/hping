/* 
 * $smu-mark$ 
 * $name: relid.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 3$ 
 */ 

/* FIXME: maybe it's better to avoid division per seq_diff and
   at least add an option to switch on/off this feature */

/* $Id: relid.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include "hping2.h"
#include "globals.h"

int relativize_id(int seqnum, int *ip_id)
{
	int seq_diff, backup_id;
	static int last_seq = 0, last_id = -1;

	backup_id = *ip_id;

	if (last_id == -1) {
		last_id = *ip_id;
		last_seq = seqnum;
	}
	else
	{
		if ( (seq_diff=(seqnum-last_seq)) > 0)
		{
			if (last_id > *ip_id) /* rew */
				*ip_id = ((65535-last_id)
				    + *ip_id)/seq_diff;
				else
				*ip_id = (*ip_id-last_id)
					/seq_diff;
			last_id = backup_id;
			last_seq = seqnum;
			return TRUE;
		} else {
			out_of_sequence_pkt++;
		}
	}
	return FALSE;
}
