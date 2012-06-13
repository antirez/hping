/*
 * $smu-mark$
 * $name: memunlock.c$
 * $other_author: Mika <mika@qualys.com>
 * $other_copyright: Copyright (C) 1999 Mika <mika@qualys.com>
 * $license: This software is under GPL version 2 of license$
 * $date: Fri Nov  5 11:55:48 MET 1999$
 * $rev: 2$
 */

/* $Id: ip_opt_build.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
                     
#include "hping2.h"
#include "globals.h"

unsigned char ip_opt_build(char* ip_opt)
{
	unsigned char optlen = 0;
	unsigned long ip;

    memset(ip_opt, 1, sizeof(ip_opt));

    if (opt_lsrr)
    {
        if (lsr_length<=39)
        {
            memcpy(ip_opt, &lsr, lsr_length);
            optlen += lsr_length;
        }
        else
        {
            printf("Warning: loose source route is too long, discarding it");
            opt_lsrr=0;
        }
    }

    if (opt_ssrr)
    {
        if (ssr_length+optlen<=39)
        {
            memcpy(ip_opt + optlen, &ssr, ssr_length);
            optlen += ssr_length;
        }
        else
        {
            printf("Warning: strict source route is too long, discarding it");
            opt_ssrr=0;
        }
    }

	if (opt_rroute)
	{
        if (optlen<=33)
        {
    		ip_opt[optlen]=IPOPT_RR;
     		ip_opt[optlen+1]=39-optlen;
    		ip_opt[optlen+2]=8;
    		ip=inet_addr("1.2.3.4");
    		memcpy(ip_opt+optlen+3,&ip,4);
            optlen=39;
        }
        else
        {
            printf("Warning: no room for record route, discarding option\n");
            opt_rroute=0;
        }
	}

    if (optlen)
    {
        optlen = (optlen + 3) & ~3;
        ip_opt[optlen-1] = 0;
        return optlen;
    }
    else
        return 0;
}

