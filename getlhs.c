/* 
 * $smu-mark$ 
 * $name: getlhs.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:47 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: getlhs.c,v 1.5 2004/04/09 23:38:56 antirez Exp $ */

#include <string.h>

#include "hping2.h"
#include "globals.h"


int dltype_to_lhs(int dltype)
{
	int lhs;

	switch(dltype) {
	case DLT_EN10MB:
#ifdef DLT_IEEE802
	case DLT_IEEE802:
#endif
		lhs = 14;
		break;
	case DLT_SLIP:
	case DLT_SLIP_BSDOS:
		lhs = 16;
		break;
	case DLT_PPP:
	case DLT_NULL:
#ifdef DLT_PPP_SERIAL
	case DLT_PPP_SERIAL:
#endif
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
		lhs = 4;
		break;
	case DLT_PPP_BSDOS:
		lhs = 24;
		break;
	case DLT_FDDI:
		lhs = 13;
		break;
	case DLT_RAW:
		lhs = 0;
		break;
#ifdef DLT_IEE802_11
	case DLT_IEEE802_11:
		lhs = 14;
		break;
#endif
	case DLT_ATM_RFC1483:
#ifdef DLT_CIP
	case DLT_CIP:
#endif
#ifdef DLT_ATM_CLIP
	case DLT_ATM_CLIP:
#endif
		lhs = 8;
		break;
#ifdef DLT_C_HDLC
	case DLT_C_HDLC:
		lhs = 4;
		break;
#endif
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
#endif
#ifdef DLT_LANE8023
	case DLT_LANE8023:
#endif
		lhs = 16;
		break;
	default:
		return -1;
		break;
	}
	return lhs;
}

int get_linkhdr_size(char *ifname)
{
	int dltype = pcap_datalink(pcapfp);

	if (opt_debug)
		printf("DEBUG: dltype is %d\n", dltype);

	linkhdr_size = dltype_to_lhs(dltype);
	return linkhdr_size;
}
