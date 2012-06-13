/* 
 * $smu-mark$ 
 * $name: sockopt.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: sockopt.c,v 1.3 2003/09/07 11:21:18 antirez Exp $ */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> /* IP_PROTOIP */
#include <stdio.h>

void socket_broadcast(int sd)
{
	const int one = 1;

	if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST,
		(char *)&one, sizeof(one)) == -1)
	{
		printf("[socket_broadcast] can't set SO_BROADCAST option\n");
		/* non fatal error */
	}
}

void socket_iphdrincl(int sd)
{
	const int one = 1;

	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL,
		(char *)&one, sizeof(one)) == -1)
	{
		printf("[socket_iphdrincl] can't set IP_HDRINCL option\n");
		/* non fatal error */
	}
}
