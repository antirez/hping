/* 
 * $smu-mark$ 
 * $name: libpcap_stuff.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:48 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: libpcap_stuff.c,v 1.3 2004/04/09 23:38:56 antirez Exp $ */

#include "hping2.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <pcap.h>
#include <net/bpf.h>

#include "globals.h"

int open_pcap()
{
	int on;

	on = 1; /* no warning if BIOCIMMEDIATE will not be compiled */
	if (opt_debug)
		printf("DEBUG: pcap_open_live(%s, 99999, 0, 1, %p)\n",
			ifname, errbuf);

	pcapfp = pcap_open_live(ifname, 99999, 0, 1, errbuf);
	if (pcapfp == NULL) {
		printf("[open_pcap] pcap_open_live: %s\n", errbuf);
		return -1;
	}
#if (!defined OSTYPE_LINUX) && (!defined __sun__)
	/* Return the packets to userspace as fast as possible */
	if (ioctl(pcap_fileno(pcapfp), BIOCIMMEDIATE, &on) == -1)
		perror("[open_pcap] ioctl(... BIOCIMMEDIATE ...)");
#endif
	return 0;
}

int close_pcap()
{
	pcap_close(pcapfp);
	return 0;
}

int pcap_recv(char *packet, unsigned int size)
{
        char *p = NULL;
        int pcapsize;

	if (opt_debug)
		printf("DEBUG: under pcap_recv()\n");

        while(p == NULL) {
                p = (unsigned char*) pcap_next(pcapfp, &hdr);
		if (p == NULL && opt_debug)
			printf("DEBUG: [pcap_recv] p = NULL\n");
	}

        pcapsize = hdr.caplen;

        if (pcapsize < size)
                size = pcapsize;

        memcpy(packet, p, pcapsize);

        return pcapsize;
}
