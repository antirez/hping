/*
 * $smu-mark$
 * $name: memunlockall.c$
 * $other_author: Alfonso De Gregorio <dira@speedcom.it>
 * $other_copyright: Copyright (C) 1999 by Alfonso De Gregorio
 * $license: This software is under GPL version 2 of license$
 * $date: Fri Nov  5 11:55:48 MET 1999$
 * $rev: 2$
 */

/* $Id: memunlockall.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <unistd.h>
#include <sys/mman.h>

int memunlockall(void)
{
/* #ifdef _POSIX_MEMLOCK */
/* NJ: better to test _POSIX_MEMLOCK value */
#if _POSIX_MEMLOCK == 1
	return ( munlockall() );
#endif
	return(-1);
}

