/* 
 * $smu-mark$ 
 * $name: version.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:50 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: version.c,v 1.3 2004/04/09 23:38:56 antirez Exp $ */

#include <stdlib.h>
#include <stdio.h>

#include "release.h"
#include "hping2.h"

void show_version(void)
{
	printf("hping version %s (%s)\n", RELEASE_VERSION, RELEASE_DATE);
#ifdef USE_TCL
	printf("This binary is TCL scripting capable\n");
#else
	printf("NO TCL scripting support compiled in\n");
#endif
	exit(0);
}

