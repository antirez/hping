/* 
 * $smu-mark$ 
 * $name: main.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:48 MET 1999$ 
 * $rev: 8$ 
 */ 

/*
 * hping official page at http://www.kyuzz.org/antirez
 * Covered by GPL version 2, Read the COPYING file for more information
 */

/* $Id: main.c,v 1.4 2004/06/18 09:53:11 antirez Exp $ */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pcap.h>

#include "hping2.h"

/* globals */
unsigned int
	tcp_th_flags = 0,
	linkhdr_size,				/* physical layer header size */
	ip_tos = 0,
	set_seqnum = FALSE,
	tcp_seqnum = FALSE,
	set_ack,
	h_if_mtu,
	virtual_mtu	= DEFAULT_VIRTUAL_MTU,
	ip_frag_offset	= 0,
	signlen,
	lsr_length = 0,
	ssr_length = 0,
	tcp_ack;


unsigned short int
	data_size = 0;

float
	rtt_min = 0,
	rtt_max = 0,
	rtt_avg = 0;

int
	sockpacket,
	sockraw,
	sent_pkt = 0,
	recv_pkt = 0,
	out_of_sequence_pkt = 0,
	sending_wait = DEFAULT_SENDINGWAIT,	/* see DEFAULT_SENDINGWAIT */
	opt_rawipmode	= FALSE,
	opt_icmpmode	= FALSE,
	opt_udpmode	= FALSE,
	opt_scanmode	= FALSE,
	opt_listenmode  = FALSE,
	opt_waitinusec	= FALSE,
	opt_numeric	= FALSE,
	opt_gethost	= TRUE,
	opt_quiet	= FALSE,
	opt_relid	= FALSE,
	opt_fragment	= FALSE,
	opt_df		= FALSE,
	opt_mf		= FALSE,
	opt_debug	= FALSE,
	opt_verbose	= FALSE,
	opt_winid_order = FALSE,
	opt_keepstill	= FALSE,
	opt_datafromfile= FALSE,
	opt_hexdump	= FALSE,
	opt_contdump	= FALSE,
	opt_sign	= FALSE,
	opt_safe	= FALSE,
	opt_end		= FALSE,
	opt_traceroute  = FALSE,
	opt_seqnum	= FALSE,
	opt_incdport	= FALSE,
	opt_force_incdport = FALSE,
	opt_icmptype	= DEFAULT_ICMP_TYPE,
	opt_icmpcode	= DEFAULT_ICMP_CODE,
	opt_rroute	= FALSE,
	opt_tcpexitcode	= FALSE,
	opt_badcksum	= FALSE,
	opt_tr_keep_ttl = FALSE,
	opt_tcp_timestamp = FALSE,
        opt_clock_skew  = FALSE,
        cs_window       = DEFAULT_CS_WINDOW,
        cs_window_shift = DEFAULT_CS_WINDOW_SHIFT,
        cs_vector_len   = DEFAULT_CS_VECTOR_LEN,
	opt_tr_stop	= FALSE,
	opt_tr_no_rtt	= FALSE,
	opt_rand_dest	= FALSE,
	opt_rand_source	= FALSE,
	opt_lsrr        = FALSE,
	opt_ssrr        = FALSE,
	opt_cplt_rte    = FALSE,
	opt_beep	= FALSE,
	opt_flood	= FALSE,
	tcp_exitcode	= 0,
	src_ttl		= DEFAULT_TTL,
	src_id		= -1, /* random */
	base_dst_port	= DEFAULT_DPORT,
	dst_port	= DEFAULT_DPORT,
	src_port,
	sequence	= 0,
	initsport	= DEFAULT_INITSPORT,
	src_winsize	= DEFAULT_SRCWINSIZE,
	src_thoff 	= (TCPHDR_SIZE >> 2),
	count		= DEFAULT_COUNT,
	ctrlzbind	= DEFAULT_BIND,
	delaytable_index= 0,
	eof_reached	= FALSE,
	icmp_ip_version = DEFAULT_ICMP_IP_VERSION,
	icmp_ip_ihl	= DEFAULT_ICMP_IP_IHL,
	icmp_ip_tos	= DEFAULT_ICMP_IP_TOS,
	icmp_ip_tot_len = DEFAULT_ICMP_IP_TOT_LEN,
	icmp_ip_id	= DEFAULT_ICMP_IP_ID,
	icmp_ip_protocol= DEFAULT_ICMP_IP_PROTOCOL,
	icmp_ip_srcport	= DEFAULT_DPORT,
	icmp_ip_dstport	= DEFAULT_DPORT,
	opt_force_icmp  = FALSE,
	icmp_cksum	= DEFAULT_ICMP_CKSUM,
	raw_ip_protocol	= DEFAULT_RAW_IP_PROTOCOL;

char
	datafilename	[1024],
	targetname	[1024],
	targetstraddr	[1024],
	ifname		[1024] = {'\0'},
	ifstraddr	[1024],
	spoofaddr	[1024],
	icmp_ip_srcip	[1024],
	icmp_ip_dstip	[1024],
	icmp_gwip	[1024],
	sign		[1024],
	rsign		[1024], /* reverse sign (hping -> gniph) */
	ip_opt		[40],
	*opt_scanports = "";

unsigned char
	lsr		[255] = {0},
	ssr		[255] = {0};

unsigned
	ip_optlen	= 0;

struct sockaddr_in
	icmp_ip_src,
	icmp_ip_dst,
	icmp_gw,
	local,
	remote;

struct itimerval usec_delay;
volatile struct delaytable_element delaytable[TABLESIZE];

struct hcmphdr *hcmphdr_p; /* global pointer used by send_hcmp to transfer
			      hcmp headers to data_handler */

pcap_t *pcapfp;
char errbuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr hdr;

/* main */
int main(int argc, char **argv)
{
	char setflags[1024] = {'\0'};
	int c, hdr_size;

	/* Check for the scripting mode */
	if (argc == 1 || (argc > 1 && !strcmp(argv[1], "exec"))) {
#ifdef USE_TCL
		if (argc != 1) {
			argv++;
			argc--;
		}
		hping_script(argc, argv);
		exit(0); /* unreached */
#else
		fprintf(stderr, "Sorry, this hping binary was compiled "
				"without TCL scripting support\n");
		exit(1);
#endif
	}

	if (parse_options(argc, argv) == -1) {
		printf("hping2: missing host argument\n"
			"Try `hping2 --help' for more information.\n");
		exit(1);
	}

	/* reverse sign */
	if (opt_sign || opt_listenmode) {
		char *src = sign+strlen(sign)-1; /* last char before '\0' */
		char *dst = rsign;

		while(src>=sign)
			*dst++ = *src--;
		*dst = '\0';
		if (opt_debug)
			printf("DEBUG: reverse sign: %s\n", rsign);
	}

	/* get target address before interface processing */
	if ((!opt_listenmode && !opt_safe) && !opt_rand_dest)
		resolve((struct sockaddr*)&remote, targetname);

	if (opt_rand_dest) {
		strlcpy(targetstraddr, targetname, sizeof(targetstraddr));
	} else {
		strlcpy(targetstraddr, inet_ntoa(remote.sin_addr),
			sizeof(targetstraddr));
	}

	/* get interface's name and address */
	if ( get_if_name() == -1 ) {
		printf("[main] no such device\n");
		exit(1);
	}

	if (opt_verbose || opt_debug) {
		printf("using %s, addr: %s, MTU: %d\n",
			ifname, ifstraddr, h_if_mtu);
	}

	/* open raw socket */
	sockraw = open_sockraw();
	if (sockraw == -1) {
		printf("[main] can't open raw socket\n");
		exit(1);
	}

	/* set SO_BROADCAST option */
	socket_broadcast(sockraw);
	/* set SO_IPHDRINCL option */
	socket_iphdrincl(sockraw);

	/* open sock packet or libpcap socket */
	if (open_pcap() == -1) {
		printf("[main] open_pcap failed\n");
		exit(1);
	}

	/* get physical layer header size */
	if ( get_linkhdr_size(ifname) == -1 ) {
		printf("[main] physical layer header size unknown\n");
		exit(1);
	}

	if (spoofaddr[0] == '\0')
		resolve((struct sockaddr*)&local, ifstraddr);
	else
		resolve((struct sockaddr*)&local, spoofaddr);

	if (icmp_ip_srcip[0] == '\0')
		resolve((struct sockaddr*)&icmp_ip_src, "1.2.3.4");
	else
		resolve((struct sockaddr*)&icmp_ip_src, icmp_ip_srcip);

	if (icmp_ip_dstip[0] == '\0')
		resolve((struct sockaddr*)&icmp_ip_dst, "5.6.7.8");
	else
		resolve((struct sockaddr*)&icmp_ip_dst, icmp_ip_dstip);

	if (icmp_gwip[0] == '\0')
		resolve((struct sockaddr*)&icmp_gw, "0.0.0.0");
	else
		resolve((struct sockaddr*)&icmp_gw, icmp_gwip);

	srand(time(NULL));

	/* set initial source port */
	if (initsport == -1)
		initsport = src_port = 1024 + (rand() % 2000);
	else
		src_port = initsport;

	for (c = 0; c < TABLESIZE; c++)
		delaytable[c].seq = -1;

	/* use SIGALRM to send packets like ping do */
	Signal(SIGALRM, send_packet);

	/* binding */
	if (ctrlzbind != BIND_NONE) Signal(SIGTSTP, inc_destparm);
	Signal(SIGINT, print_statistics);
	Signal(SIGTERM, print_statistics);

	/* if we are in listemode enter in listenmain() else  */
	/* print HPING... bla bla bla and enter in wait_packet() */
	if (opt_listenmode) {
		fprintf(stderr, "hping2 listen mode\n");

		/* memory protection */
		if (memlockall() == -1) {
			perror("[main] memlockall()");
			fprintf(stderr, "Warning: can't disable memory paging!\n");
		} else if (opt_verbose || opt_debug) {
			printf("Memory paging disabled\n");
		}
		listenmain();
		/* UNREACHED */
	}

	/* Scan mode */
	if (opt_scanmode) {
		fprintf(stderr, "Scanning %s (%s), port %s\n",
				targetname, targetstraddr, opt_scanports);
		scanmain();
		/* UNREACHED */
	}

	if (opt_rawipmode) {
		strcat(setflags, "raw IP mode");
		hdr_size = IPHDR_SIZE;
	} else if (opt_icmpmode) {
		strcat(setflags, "icmp mode");
		hdr_size = IPHDR_SIZE + ICMPHDR_SIZE;
	} else if (opt_udpmode) {
		strcat(setflags, "udp mode");
		hdr_size = IPHDR_SIZE + UDPHDR_SIZE;
	} else {
		if (tcp_th_flags & TH_RST)  strcat(setflags, "R");
		if (tcp_th_flags & TH_SYN)  strcat(setflags, "S");
		if (tcp_th_flags & TH_ACK)  strcat(setflags, "A");
		if (tcp_th_flags & TH_FIN)  strcat(setflags, "F");
		if (tcp_th_flags & TH_PUSH) strcat(setflags, "P");
		if (tcp_th_flags & TH_URG)  strcat(setflags, "U");
		if (tcp_th_flags & TH_X)    strcat(setflags, "X");
		if (tcp_th_flags & TH_Y)    strcat(setflags, "Y");
		if (setflags[0] == '\0')    strcat(setflags, "NO FLAGS are");
		hdr_size = IPHDR_SIZE + TCPHDR_SIZE;
	}
	
	printf("HPING %s (%s %s): %s set, %d headers + %d data bytes\n",
		targetname,
		ifname,
		targetstraddr,
		setflags,
		hdr_size,
		data_size);

	/* memory protection */
	if (opt_datafromfile || opt_sign) {
		if (memlockall() == -1) {
			perror("[main] memlockall()");
			fprintf(stderr,
				"Warning: can't disable memory paging!\n");
		} else if (opt_verbose || opt_debug) {
			printf("Memory paging disabled\n");
		}
	}

	/* start packet sending */
	kill(getpid(), SIGALRM);

	/* flood mode? */
	if (opt_flood) {
		fprintf(stderr,
			"hping in flood mode, no replies will be shown\n");
		while (1) {
			send_packet(0);
		}
	}

	/* main loop */
	while(1)
		wait_packet();

	return 0;
}
