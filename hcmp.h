/* 
 * $smu-mark$ 
 * $name: hcmp.h$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:47 MET 1999$ 
 * $rev: 9$ 
 */ 

/* Hping Control Message Protocol */

#define HCMP_RESTART		1
#define HCMP_SOURCE_QUENCH	2
#define HCMP_SOURCE_STIRUP	3
#define HCMP_CHPROTO		4 /* still unused */

struct hcmphdr
{
	__u8	type;
	union
	{
		__u16 seqnum;
		__u32 usec;
	} typedep;
};
