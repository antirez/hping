/* $Id: sendrawip.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "hping2.h"
#include "globals.h"

void send_rawip(void)
{
	char *packet;

	packet = malloc(data_size);
	if (packet == NULL) {
		perror("[send_rawip] malloc()");
		return;
	}
	memset(packet, 0, data_size);
	data_handler(packet, data_size);
	send_ip_handler(packet, data_size);
	free(packet);
}
