/* Glue between hping and the ars engine */

/* $Id: arsglue.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdlib.h>
#include <stdio.h>
#include "ars.h"

/* Send the APD described packet {s} */
void hping_ars_send(char *apd)
{
	struct ars_packet p;
	int s;

	ars_init(&p);
	s = ars_open_rawsocket(&p);
	if (s == -ARS_ERROR) {
		perror("Opening raw socket");
		exit(1);
	}
	if (ars_d_build(&p, apd) != -ARS_OK) {
		fprintf(stderr, "APD error: %s\n", p.p_error);
		exit(1);
	}
	if (ars_compile(&p) != -ARS_OK) {
		fprintf(stderr, "APD error compiling: %s\n", p.p_error);
		exit(1);
	}
	if (ars_send(s, &p, NULL, 0) != -ARS_OK) {
		perror("Sending the packet");
		exit(1);
	}
	exit(0);
}
