/* Copyright (C) 2000,2001 Salvatore Sanfilippo <antirez@invece.org> */

#ifndef ARS_IPPROTO_IP

#define ARS_IPPROTO_IP 		0 /* Dummy protocol for TCP. */
#define ARS_IPPROTO_HOPOPTS 	0 /* IPv6 Hop-by-Hop options. */
#define ARS_IPPROTO_ICMP	1 /* Internet Control Message Protocol. */
#define ARS_IPPROTO_IGMP	2 /* Internet Group Management Protocol. */
#define ARS_IPPROTO_IPIP	4 /* IPIP tunnels (older KA9Q tunnels use 94).*/
#define ARS_IPPROTO_TCP		6 /* Transmission Control Protocol.  */
#define ARS_IPPROTO_EGP		8 /* Exterior Gateway Protocol.  */
#define ARS_IPPROTO_IGRP	9 /* Cisco(R)'s IGRP Routing Portocol. */
#define ARS_IPPROTO_PUP		12 /* PUP protocol.  */
#define ARS_IPPROTO_UDP		17 /* User Datagram Protocol.  */
#define ARS_IPPROTO_IDP		22 /* XNS IDP protocol.  */
#define ARS_IPPROTO_TP		29 /* SO Transport Protocol Class 4.  */
#define ARS_IPPROTO_IPV6	41 /* IPv6 header.  */
#define ARS_IPPROTO_ROUTING	43 /* IPv6 routing header.  */
#define ARS_IPPROTO_FRAGMENT	44 /* IPv6 fragmentation header.  */
#define ARS_IPPROTO_RSVP	46 /* Reservation Protocol.  */
#define ARS_IPPROTO_GRE		47 /* General Routing Encapsulation.  */
#define ARS_IPPROTO_ESP		50 /* encapsulating security payload.  */
#define ARS_IPPROTO_AH		51 /* authentication header.  */
#define ARS_IPPROTO_ICMPV6	58 /* ICMPv6.  */
#define ARS_IPPROTO_NONE	59 /* IPv6 no next header.  */
#define ARS_IPPROTO_DSTOPTS	60 /* IPv6 destination options.  */
#define ARS_IPPROTO_MTP		92 /* Multicast Transport Protocol.  */
#define ARS_IPPROTO_ENCAP	98 /* Encapsulation Header.  */
#define ARS_IPPROTO_PIM		103 /* Protocol Independent Multicast.  */
#define ARS_IPPROTO_COMP	108 /* Compression Header Protocol.  */
#define ARS_IPPROTO_RAW		255 /* Raw IP packets.  */

#endif
