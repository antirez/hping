/* 
 * $smu-mark$ 
 * $name: gethostname.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:47 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: gethostname.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

size_t strlcpy(char *dst, const char *src, size_t siz);

char *get_hostname(char* addr)
{
	static char answer[1024];
	static char lastreq[1024] = {'\0'};	/* last request */
	struct hostent *he;
	struct in_addr naddr;
	static char *last_answerp = NULL;

	printf(" get hostname..."); fflush(stdout);
	printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b"
		"               "
		"\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");

	if (!strcmp(addr, lastreq))
		return last_answerp;

	strlcpy(lastreq, addr, 1024);
	inet_aton(addr, &naddr);
	he = gethostbyaddr((char*)&naddr, 4, AF_INET);

	if (he == NULL) {
		last_answerp = NULL;
		return NULL;
	}

	strlcpy(answer, he->h_name, 1024);
	last_answerp = answer;

	return answer;
}

