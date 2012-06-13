/* 
 * $smu-mark$ 
 * $name: logicmp.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:48 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: logicmp.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>
#include <sys/types.h> /* this should be not needed, but ip_icmp.h lacks it */

#include "hping2.h"
#include "globals.h"

void log_icmp_timeexc(char *src_addr, unsigned short icmp_code)
{
	switch(icmp_code) {
	case ICMP_EXC_TTL:
		printf("TTL 0 during transit from ip=%s", src_addr);
		break;
	case ICMP_EXC_FRAGTIME:
		printf("TTL 0 during reassembly from ip=%s", src_addr);
		break;
	}
	if (opt_gethost) {
		char *hostn;

		fflush(stdout);
		hostn = get_hostname(src_addr);
		printf("name=%s", (hostn) ? hostn : "UNKNOWN");
	}
	putchar('\n');
}
		
void log_icmp_unreach(char *src_addr, unsigned short icmp_code)
{
	static char* icmp_unreach_msg[]={
	"Network Unreachable from",		/* code 0 */
	"Host Unreachable from",		/* code 1 */
	"Protocol Unreachable from",		/* code 2 */
	"Port Unreachable from",		/* code 3 */
	"Fragmentation Needed/DF set from",	/* code 4 */
	"Source Route failed from",		/* code 5 */
	NULL,					/* code 6 */
	NULL,					/* code 7 */
	NULL,					/* code 8 */
	NULL,					/* code 9 */
	NULL,					/* code 10 */
	NULL,					/* code 11 */
	NULL,					/* code 12 */
	"Packet filtered from",			/* code 13 */
	"Precedence violation from",		/* code 14 */
	"precedence cut off from"		/* code 15 */
	};
	
	if (icmp_unreach_msg[icmp_code] != NULL)
		printf("ICMP %s ip=%s", icmp_unreach_msg[icmp_code], src_addr);
	else
		printf("ICMP Unreachable type=%d from ip=%s",
			icmp_code, src_addr);

	if (opt_gethost) {
		char *hostn;

		fflush(stdout);
		hostn = get_hostname(src_addr);
		printf("name=%s", (hostn) ? hostn : "UNKNOWN");
	}
	putchar('\n');
}
