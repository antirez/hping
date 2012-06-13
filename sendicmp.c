/* 
 * $smu-mark$ 
 * $name: sendicmp.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: sendicmp.c,v 1.1.1.1 2003/08/31 17:23:53 antirez Exp $ */

#include <sys/types.h> /* this should be not needed, but ip_icmp.h lacks it */
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "hping2.h"
#include "globals.h"

static int _icmp_seq = 0;

void send_icmp_echo(void);
void send_icmp_other(void);
void send_icmp_timestamp(void);
void send_icmp_address(void);

void send_icmp(void)
{
	switch(opt_icmptype)
	{
		case ICMP_ECHO:			/* type 8 */
		case ICMP_ECHOREPLY:		/* type 0 */
			send_icmp_echo();
			break;
		case ICMP_DEST_UNREACH:		/* type 3 */
		case ICMP_SOURCE_QUENCH:	/* type 4 */
		case ICMP_REDIRECT:		/* type 5 */
		case ICMP_TIME_EXCEEDED:	/* type 11 */
			send_icmp_other();
			break;
		case ICMP_TIMESTAMP:
		case ICMP_TIMESTAMPREPLY:
			send_icmp_timestamp();
			break;
		case ICMP_ADDRESS:
		case ICMP_ADDRESSREPLY:
			send_icmp_address();
			break;
		default:
			if (opt_force_icmp) {
			    send_icmp_other();
			    break;
			} else {
			    printf("[send_icmp] Unsupported icmp type!\n");
			    exit(1);
			}
	}
}

void send_icmp_echo(void)
{
	char *packet, *data;
	struct myicmphdr *icmp;

	packet = malloc(ICMPHDR_SIZE + data_size);
	if (packet == NULL) {
		perror("[send_icmp] malloc");
		return;
	}

	memset(packet, 0, ICMPHDR_SIZE + data_size);

	icmp = (struct myicmphdr*) packet;
	data = packet + ICMPHDR_SIZE;

	/* fill icmp hdr */
	icmp->type = opt_icmptype;	/* echo replay or echo request */
	icmp->code = opt_icmpcode;	/* should be indifferent */
	icmp->checksum = 0;
	icmp->un.echo.id = getpid() & 0xffff;
	icmp->un.echo.sequence = _icmp_seq;

	/* data */
	data_handler(data, data_size);

	/* icmp checksum */
	if (icmp_cksum == -1)
		icmp->checksum = cksum((u_short*)packet, ICMPHDR_SIZE + data_size);
	else
		icmp->checksum = icmp_cksum;

	/* adds this pkt in delaytable */
	if (opt_icmptype == ICMP_ECHO)
		delaytable_add(_icmp_seq, 0, time(NULL), get_usec(), S_SENT);

	/* send packet */
	send_ip_handler(packet, ICMPHDR_SIZE + data_size);
	free (packet);

	_icmp_seq++;
}

void send_icmp_timestamp(void)
{
	char *packet;
	struct myicmphdr *icmp;
	struct icmp_tstamp_data *tstamp_data;

	packet = malloc(ICMPHDR_SIZE + sizeof(struct icmp_tstamp_data));
	if (packet == NULL) {
		perror("[send_icmp] malloc");
		return;
	}

	memset(packet, 0, ICMPHDR_SIZE + sizeof(struct icmp_tstamp_data));

	icmp = (struct myicmphdr*) packet;
	tstamp_data = (struct icmp_tstamp_data*) (packet + ICMPHDR_SIZE);

	/* fill icmp hdr */
	icmp->type = opt_icmptype;	/* echo replay or echo request */
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.id = getpid() & 0xffff;
	icmp->un.echo.sequence = _icmp_seq;
	tstamp_data->orig = htonl(get_midnight_ut_ms());
	tstamp_data->recv = tstamp_data->tran = 0;

	/* icmp checksum */
	if (icmp_cksum == -1)
		icmp->checksum = cksum((u_short*)packet, ICMPHDR_SIZE +
				sizeof(struct icmp_tstamp_data));
	else
		icmp->checksum = icmp_cksum;

	/* adds this pkt in delaytable */
	if (opt_icmptype == ICMP_TIMESTAMP)
		delaytable_add(_icmp_seq, 0, time(NULL), get_usec(), S_SENT);

	/* send packet */
	send_ip_handler(packet, ICMPHDR_SIZE + sizeof(struct icmp_tstamp_data));
	free (packet);

	_icmp_seq++;
}

void send_icmp_address(void)
{
	char *packet;
	struct myicmphdr *icmp;

	packet = malloc(ICMPHDR_SIZE + 4);
	if (packet == NULL) {
		perror("[send_icmp] malloc");
		return;
	}

	memset(packet, 0, ICMPHDR_SIZE + 4);

	icmp = (struct myicmphdr*) packet;

	/* fill icmp hdr */
	icmp->type = opt_icmptype;	/* echo replay or echo request */
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.id = getpid() & 0xffff;
	icmp->un.echo.sequence = _icmp_seq;
	memset(packet+ICMPHDR_SIZE, 0, 4);

	/* icmp checksum */
	if (icmp_cksum == -1)
		icmp->checksum = cksum((u_short*)packet, ICMPHDR_SIZE + 4);
	else
		icmp->checksum = icmp_cksum;

	/* adds this pkt in delaytable */
	if (opt_icmptype == ICMP_TIMESTAMP)
		delaytable_add(_icmp_seq, 0, time(NULL), get_usec(), S_SENT);

	/* send packet */
	send_ip_handler(packet, ICMPHDR_SIZE + 4);
	free (packet);

	_icmp_seq++;
}

void send_icmp_other(void)
{
	char *packet, *data, *ph_buf;
	struct myicmphdr *icmp;
	struct myiphdr icmp_ip;
	struct myudphdr *icmp_udp;
	int udp_data_len = 0;
	struct pseudohdr *pseudoheader;
	int left_space = IPHDR_SIZE + UDPHDR_SIZE + data_size;

	packet = malloc(ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
	ph_buf = malloc(PSEUDOHDR_SIZE + UDPHDR_SIZE + udp_data_len);
	if (packet == NULL || ph_buf == NULL) {
		perror("[send_icmp] malloc");
		return;
	}

	memset(packet, 0, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
	memset(ph_buf, 0, PSEUDOHDR_SIZE + UDPHDR_SIZE + udp_data_len);

	icmp = (struct myicmphdr*) packet;
	data = packet + ICMPHDR_SIZE;
	pseudoheader = (struct pseudohdr *) ph_buf;
	icmp_udp = (struct myudphdr *) (ph_buf + PSEUDOHDR_SIZE);

	/* fill icmp hdr */
	icmp->type = opt_icmptype;	/* ICMP_TIME_EXCEEDED */
	icmp->code = opt_icmpcode;	/* should be 0 (TTL) or 1 (FRAGTIME) */
	icmp->checksum = 0;
	if (opt_icmptype == ICMP_REDIRECT)
		memcpy(&icmp->un.gateway, &icmp_gw.sin_addr.s_addr, 4);
	else
		icmp->un.gateway = 0;	/* not used, MUST be 0 */

	/* concerned packet headers */
	/* IP header */
	icmp_ip.version  = icmp_ip_version;		/* 4 */
	icmp_ip.ihl      = icmp_ip_ihl;			/* IPHDR_SIZE >> 2 */
	icmp_ip.tos      = icmp_ip_tos;			/* 0 */
	icmp_ip.tot_len  = htons((icmp_ip_tot_len ? icmp_ip_tot_len : (icmp_ip_ihl<<2) + UDPHDR_SIZE + udp_data_len));
	icmp_ip.id       = htons(getpid() & 0xffff);
	icmp_ip.frag_off = 0;				/* 0 */
	icmp_ip.ttl      = 64;				/* 64 */
	icmp_ip.protocol = icmp_ip_protocol;		/* 6 (TCP) */
	icmp_ip.check	 = 0;
	memcpy(&icmp_ip.saddr, &icmp_ip_src.sin_addr.s_addr, 4);
	memcpy(&icmp_ip.daddr, &icmp_ip_dst.sin_addr.s_addr, 4);
	icmp_ip.check	 = cksum((__u16 *) &icmp_ip, IPHDR_SIZE);

	/* UDP header */
	memcpy(&pseudoheader->saddr, &icmp_ip_src.sin_addr.s_addr, 4);
	memcpy(&pseudoheader->daddr, &icmp_ip_dst.sin_addr.s_addr, 4);
	pseudoheader->protocol = icmp_ip.protocol;
	pseudoheader->lenght = icmp_ip.tot_len;
	icmp_udp->uh_sport = htons(icmp_ip_srcport);
	icmp_udp->uh_dport = htons(icmp_ip_dstport);
	icmp_udp->uh_ulen  = htons(UDPHDR_SIZE + udp_data_len);
	icmp_udp->uh_sum   = cksum((__u16 *) ph_buf, PSEUDOHDR_SIZE + UDPHDR_SIZE + udp_data_len);

	/* filling icmp body with concerned packet header */

	/* fill IP */
	if (left_space == 0) goto no_space_left;
	memcpy(packet+ICMPHDR_SIZE, &icmp_ip, left_space);
	left_space -= IPHDR_SIZE;
	data += IPHDR_SIZE;
	if (left_space <= 0) goto no_space_left;

	/* fill UDP */
	memcpy(packet+ICMPHDR_SIZE+IPHDR_SIZE, icmp_udp, left_space);
	left_space -= UDPHDR_SIZE;
	data += UDPHDR_SIZE;
	if (left_space <= 0) goto no_space_left;

	/* fill DATA */
	data_handler(data, left_space);
no_space_left:

	/* icmp checksum */
	if (icmp_cksum == -1)
		icmp->checksum = cksum((u_short*)packet, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
	else
		icmp->checksum = icmp_cksum;

	/* send packet */
	send_ip_handler(packet, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
	free (packet);
	free (ph_buf);
}
