/* 
 * $smu-mark$ 
 * $name: if_promisc.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:48 MET 1999$ 
 * $rev: 2$ 
 */ 

/* $Id: if_promisc.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>

#include "hping2.h"
#include "globals.h"

int if_promisc_on(int s)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if ( ioctl(s, SIOCGIFFLAGS, &ifr) == -1) {
		perror("[if_prommisc_on] ioctl(SIOCGIFFLAGS)");
		return -1;
	}

	if (!(ifr.ifr_flags & IFF_PROMISC)) {
		ifr.ifr_flags |= IFF_PROMISC;
		if ( ioctl(s, SIOCSIFFLAGS, &ifr) == -1) {
			perror("[if_promisc_on] ioctl(SIOCSIFFLAGS)");
			return -1;
		}
	}
	return 0;
}

int if_promisc_off(int s)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if ( ioctl(s, SIOCGIFFLAGS, &ifr) == -1) {
		perror("[if_promisc_off] ioctl(SIOCGIFFLAGS)");
		return -1;
	}

	if (ifr.ifr_flags & IFF_PROMISC) {
		ifr.ifr_flags ^= IFF_PROMISC;
		if ( ioctl(s, SIOCSIFFLAGS, &ifr) == -1) {
			perror("[if_promisc_off] ioctl(SIOCSIFFLAGS)");
			return -1;
		}
	}
	return 0;
}
