/* 
 * $smu-mark$ 
 * $name: getusec.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:47 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: getusec.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <sys/time.h>
#include <stdlib.h>

time_t get_usec(void)
{
	struct timeval tmptv;

	gettimeofday(&tmptv, NULL);
	return tmptv.tv_usec;
}

time_t milliseconds(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
}

/* This function returns milliseconds since 1 Jan 1970,
 * so it's like time() but with milliseconds resolution.
 * We use this function mainly for physical fingerpriting
 * via TCP timestamp. */
long long mstime(void)
{
        struct timeval tmptv;

        gettimeofday(&tmptv, NULL);
        return ((long long)tmptv.tv_sec*1000)+(tmptv.tv_usec/1000);
}
