/*
 * $smu-mark$
 * $name: memunlock.c$
 * $other_author: Alfonso De Gregorio <dira@speedcom.it>
 * $other_copyright: Copyright (C) 1999 by Alfonso De Gregorio
 * $license: This software is under GPL version 2 of license$
 * $date: Fri Nov  5 11:55:48 MET 1999$
 * $rev: 2$
 */

/* $Id: memunlock.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <unistd.h>
#include <sys/mman.h>

int memunlock(char *addr, size_t size)
{
#ifdef _POSIX_MEMLOCK_RANGE
	unsigned long    page_offset, page_size;

	page_size = sysconf(_SC_PAGESIZE);
	page_offset = (unsigned long) addr % page_size;

	addr -= page_offset; 
	size += page_offset;

	return ( munlock(addr, size) ); 
#endif
	return (-1);
}
