/* 
 * $smu-mark$ 
 * $name: datafiller.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:47 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: datafiller.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h> /* memset */

#include "hping2.h"
#include "globals.h"

void datafiller(char *p, int size)
{
	static int fd = 0;
	int readed, diff;

	if (!fd) {
		fd = open(datafilename, O_RDONLY);
		if (fd == -1) {
			perror("[datafiller] open()");
			fd = 0; /* will retry to open the file for
				 * the next packet */
			memset(p, 'X', size);
			return;
		}
	}

	if (p == NULL && fd != -1) { /* seek operation */
		/* size-1 because packet with id 1 start from 0 */
		lseek(fd, (data_size-signlen)*(size-1), SEEK_SET);
		return;
	}

restart: /* if EOF occurs, after rewind, restart */

	readed = read(fd, p, size);
	if (readed == size)
		return;
	else if (readed == -1) {
		perror("[datafiller] read()");
		close(fd);
		fd = 0; /* will retry to open the file for the next packet */
		memset(p, 'X', size);
		return;
	}
	else if (readed < size && opt_end == FALSE) {
		lseek(fd, 0, SEEK_SET);
		if (readed == 0)
			goto restart;
	}
	else if (readed < size && opt_end == TRUE) {
		fprintf(stderr, "EOF reached, wait some second than press "
				"ctrl+c\n");
		eof_reached = TRUE;
	} else {
		printf("[datafiller.c INTERNAL ERROR] readed = %d - "
			"opt_end == %d\n", readed, opt_end);
		exit(1);
	}
	diff = size - readed;
	memset(p+readed, '\0', diff); /* padding */
	lseek(fd, 0, SEEK_SET);
	return;
}
