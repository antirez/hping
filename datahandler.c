/* 
 * $smu-mark$ 
 * $name: datahandler.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:47 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: datahandler.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <string.h>

#include "hping2.h"
#include "globals.h"

void data_handler(char *data, int data_size)
{
	if (opt_listenmode) { /* send an HCMP */
		memcpy(data, rsign, signlen); /* ok, write own reverse sign */
		data+=signlen;
		data_size-=signlen;
		memcpy(data, hcmphdr_p, data_size);
		return; /* done */
	}

	if (opt_sign) {
		memcpy(data, sign, signlen); /* lenght pre-checked */
		data+=signlen;
		data_size-=signlen;
	}

	if (data_size == 0)
		return; /* there is not space left */

	if (opt_datafromfile)
		datafiller(data, data_size);
	else
		memset(data, 'X', data_size);
}
