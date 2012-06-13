/* 
 * $smu-mark$ 
 * $name: sendip_handler.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 3$ 
 */ 

/* $Id: sendip_handler.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>

#include "hping2.h"
#include "globals.h"

void send_ip_handler(char *packet, unsigned int size)
{
	ip_optlen = ip_opt_build(ip_opt);

	if (!opt_fragment && (size+ip_optlen+20 >= h_if_mtu))
	{
		/* auto-activate fragmentation */
		virtual_mtu = h_if_mtu-20;
		virtual_mtu = virtual_mtu - (virtual_mtu % 8);
		opt_fragment = TRUE;
		opt_mf = opt_df = FALSE; /* deactivate incompatible options */
		if (opt_verbose || opt_debug)
			printf("auto-activate fragmentation, fragments size: %d\n", virtual_mtu);
	}

	if (!opt_fragment)
	{
		unsigned short fragment_flag = 0;

		if (opt_mf) fragment_flag |= MF; /* more fragments */
		if (opt_df) fragment_flag |= DF; /* dont fragment */
		send_ip((char*)&local.sin_addr,
			(char*)&remote.sin_addr,
			packet, size, fragment_flag, ip_frag_offset,
			ip_opt, ip_optlen);
	}
	else
	{
		unsigned int remainder = size;
		int frag_offset = 0;

		while(1) {
			if (remainder <= virtual_mtu)
				break;

			send_ip((char*)&local.sin_addr,
				(char*)&remote.sin_addr,
				packet+frag_offset,
				virtual_mtu, MF, frag_offset,
				ip_opt, ip_optlen);

			remainder-=virtual_mtu;
			frag_offset+=virtual_mtu;
		}

		send_ip((char*)&local.sin_addr,
			(char*)&remote.sin_addr,
			packet+frag_offset,
			remainder, NF, frag_offset,
			ip_opt, ip_optlen);
	}
}
