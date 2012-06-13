/* 
 * $smu-mark$ 
 * $name: globals.h$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:47 MET 1999$ 
 * $rev: 9$ 
 */ 

/* $Id: globals.h,v 1.3 2004/06/18 09:53:11 antirez Exp $ */

#ifndef _GLOBALS_H
#define _GLOBALS_H

extern float
		rtt_min,
		rtt_max,
		rtt_avg;

extern unsigned int
		tcp_th_flags,
		linkhdr_size,
		h_if_mtu,
		virtual_mtu,
		ip_frag_offset,
		signlen,
		lsr_length,
		ssr_length,
		ip_tos,
		set_seqnum,
		tcp_seqnum,
		set_ack,
		ip_header_length,
		tcp_ack;

extern unsigned short int
		data_size;

extern int	opt_debug,
		sockpacket,
		sockraw,
		sent_pkt,
		recv_pkt,
		out_of_sequence_pkt,
		sending_wait,
		opt_rawipmode,
		opt_icmpmode,
		opt_udpmode,
		opt_scanmode,
		opt_listenmode,
		opt_waitinusec,
		opt_numeric,
		opt_gethost,
		opt_quiet,
		opt_relid,
		opt_fragment,
		opt_df,
		opt_mf,
		opt_debug,
		opt_verbose,
		opt_winid_order,
		opt_keepstill,
		opt_datafromfile,
		opt_hexdump,
		opt_contdump,
		opt_sign,
		opt_safe,
		opt_end,
		opt_traceroute,
		opt_seqnum,
		opt_incdport,
		opt_force_incdport,
		opt_icmptype,
		opt_icmpcode,
		opt_rroute,
		opt_tcpexitcode,
		opt_badcksum,
		opt_tr_keep_ttl,
		opt_tcp_timestamp,
                opt_clock_skew,
                cs_window,
                cs_window_shift,
                cs_vector_len,
		opt_tr_stop,
		opt_tr_no_rtt,
		opt_rand_dest,
		opt_rand_source,
		opt_lsrr,
		opt_ssrr,
		opt_beep,
		opt_flood,
		tcp_exitcode,
		src_ttl,
		src_id,
		base_dst_port,
		dst_port,
		src_port,
		initsport,
		sequence,
		src_winsize,
		src_thoff,
		count,
		ctrlzbind,
		delaytable_index,
		eof_reached,
		icmp_ip_version,
		icmp_ip_ihl,
		icmp_ip_tos,
		icmp_ip_tot_len,
		icmp_ip_id,
		icmp_ip_srcport,
		icmp_ip_dstport,
		opt_force_icmp,
		icmp_ip_protocol,
		icmp_cksum,
		raw_ip_protocol;

extern unsigned char 	lsr[255],
			ssr[255];

extern char	ifname[1024],
		ifstraddr[1024],
		datafilename[1024],
		targetname[1024],
		targetstraddr[1024],
		spoofaddr[1024],
		icmp_ip_srcip[1024],
		icmp_ip_dstip[1024],
		icmp_gwip[1024],
		sign[1024],
		rsign[1024],
		ip_opt[40],
		ip_optlen,
		*opt_scanports;

extern struct sockaddr_in icmp_ip_src, icmp_ip_dst, icmp_gw, local, remote;
extern struct itimerval usec_delay;
extern volatile struct delaytable_element delaytable[TABLESIZE];
extern struct hcmphdr *hcmphdr_p;

#include <pcap.h>
extern pcap_t *pcapfp;
extern char errbuf[PCAP_ERRBUF_SIZE];
extern struct pcap_pkthdr hdr;

#endif /* _GLOBALS_H */
