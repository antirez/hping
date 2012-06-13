/* $Id: cksum.c,v 1.3 2004/04/14 12:30:18 antirez Exp $  */

#include "hping2.h"	/* only for arch semi-indipendent data types */
#include "globals.h"

/*
 * from R. Stevens's Network Programming
 */
__u16 cksum(__u16 *buf, int nbytes)
{
	__u32 sum;
	__u16 oddbyte;

	sum = 0;
	while (nbytes > 1) {
		sum += *buf++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((__u16 *) &oddbyte) = *(__u16 *) buf;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	/* return a bad checksum with --badcksum option */
	if (opt_badcksum) sum ^= 0x5555;

	return (__u16) ~sum;
}
