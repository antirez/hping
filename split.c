/* Copyright (C) 2003 Salvatore Sanfilippo
 * All rights reserved
 * $Id: split.c,v 1.4 2003/09/07 11:21:18 antirez Exp $ */

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "ars.h"

int ars_seems_ip(struct ars_iphdr *ip, size_t size)
{
	if (ip->version == 4 &&
	    ip->ihl >= 5 &&
	    (ip->ihl << 2) <= size &&
	    ars_check_ip_cksum(ip) == 1)
		return 1;
	return 0;
}

int ars_guess_ipoff(void *packet, size_t size, int *lhs)
{
	size_t orig_size = size;

	while(1) {
		struct ars_iphdr *ip = packet;
		if (size < sizeof (struct ars_iphdr))
			break;
		if (ars_seems_ip(ip, size) == 0) {
			/* We may probably assume the link header size
			 * to be multiple of two */
			packet++;
			size--;
			continue;
		}
		*lhs = orig_size - size;
		return -ARS_OK;
	}
	return -ARS_ERROR;
}

int ars_check_ip_cksum(struct ars_iphdr *ip)
{
	int ip_hdrsize = ip->ihl << 2;
	struct ars_iphdr *ip2;

	ip2 = alloca(ip_hdrsize);
	memcpy(ip2, ip, ip_hdrsize);
	ip2->check = 0;
	ip2->check = ars_cksum(ip2, ip_hdrsize);
	return (ip->check == ip2->check);
}

int ars_check_icmp_cksum(struct ars_icmphdr *icmp, size_t size)
{
	struct ars_icmphdr *icmp2;

	icmp2 = alloca(size);
	memcpy(icmp2, icmp, size);
	icmp2->checksum = 0;
	icmp2->checksum = ars_cksum(icmp2, size);
	return (icmp->checksum == icmp2->checksum);
}

#define ARS_SPLIT_DONE		0
#define ARS_SPLIT_GET_IP	1
#define ARS_SPLIT_GET_IPOPT	2
#define ARS_SPLIT_GET_ICMP	3
#define ARS_SPLIT_GET_UDP	4
#define ARS_SPLIT_GET_TCP	5
#define ARS_SPLIT_GET_TCPOPT	6
#define ARS_SPLIT_GET_IGRP	7
#define ARS_SPLIT_GET_IGRPENTRY	8
#define ARS_SPLIT_GET_DATA	9

int ars_split_ip(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_ipopt(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_icmp(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_udp(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_tcp(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_tcpopt(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_igrp(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_igrpentry(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_data(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);

/* Take it in sync with ARS_SPLIT_* defines */
int (*ars_split_state_handler[])(struct ars_packet *pkt, void *packet,
				size_t size, int *state, int *len) =
{
	NULL,
	ars_split_ip,
	ars_split_ipopt,
	ars_split_icmp,
	ars_split_udp,
	ars_split_tcp,
	ars_split_tcpopt,
	ars_split_igrp,
	ars_split_igrpentry,
	ars_split_data
};

int ars_split_packet(void *packet, size_t size, int ipoff, struct ars_packet *pkt)
{
	int offset = 0;
	int state = ARS_SPLIT_GET_IP;

	/* User asks for IP offset auto detection */
	if (ipoff == -1 && ars_guess_ipoff(packet, size, &ipoff) != -ARS_OK) {
		ars_set_error(pkt, "IP offset autodetection failed");
		return -ARS_INVALID;
	}
	offset += ipoff;
	size -= ipoff;

	/* Implemented as a finite state machine:
	 * every state is handled with a protocol specific function */
	while (state != ARS_SPLIT_DONE) {
		int error;
		int len = 0;

		error = ars_split_state_handler[state](pkt, packet + offset,
						size, &state, &len);
		if (error != -ARS_OK)
			return error;
		/* put off the link layer padding */
		if (pkt->p_layer_nr == 1 &&
		    pkt->p_layer[0].l_type == ARS_TYPE_IP) {
			struct ars_iphdr *ip =  pkt->p_layer[0].l_data;
			size = MIN(size, ntohs(ip->tot_len));
		}
		offset += len;
		size -= len;
		/* Force the DONE state if we reached the end */
		if (size == 0)
			state = ARS_SPLIT_DONE;
	}
	return -ARS_OK;
}

/* Select the right state based on the IP protocol field */
void ars_ip_next_state(int ipproto, int *state)
{
	switch(ipproto) {
	case ARS_IPPROTO_IPIP:
		*state = ARS_SPLIT_GET_IP;
		break;
	case ARS_IPPROTO_ICMP:
		*state = ARS_SPLIT_GET_ICMP;
		break;
	case ARS_IPPROTO_TCP:
		*state = ARS_SPLIT_GET_TCP;
		break;
	case ARS_IPPROTO_UDP:
		*state = ARS_SPLIT_GET_UDP;
		break;
	case ARS_IPPROTO_IGRP:
		*state = ARS_SPLIT_GET_IGRP;
		break;
	default:
		*state = ARS_SPLIT_GET_DATA;
		break;
	}
}

int ars_split_ip(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_iphdr *ip = packet, *newip;
	int flags = 0;
	int ipsize;
	

	/* Check for bad header size and checksum */
	if (size < sizeof(struct ars_iphdr)) {
		flags |= ARS_SPLIT_FTRUNC;
		ipsize = size;
	} else {
		ipsize = ip->ihl << 2;
		if (size < ipsize) {
			flags |= ARS_SPLIT_FTRUNC;
			ipsize = size;
		}
		else if (ip->ihl < 4 || ars_check_ip_cksum(ip) == 0)
			flags |= ARS_SPLIT_FBADCKSUM;
		ipsize = MIN(ipsize, 20);
	}
	if ((newip = ars_add_iphdr(pkt, 0)) == NULL)
		return -ARS_NOMEM;

	memcpy(newip, ip, ipsize);
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);
	*len = ipsize;

	if (flags & ARS_SPLIT_FTRUNC) {
		*state = ARS_SPLIT_GET_DATA;
		return -ARS_OK;
	}

	if (ip->ihl > 5) { /* IP options */
		/* IP protocol saved so after the IP option
		 * processing we can start with the right status */
		pkt->aux_ipproto = ip->protocol;
		*state = ARS_SPLIT_GET_IPOPT;
		pkt->aux = (ip->ihl - 5) << 2;
		return -ARS_OK;
	}
	ars_ip_next_state(ip->protocol, state);
	return -ARS_OK;
}

int ars_split_ipopt(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_ipopt *ipopt = packet;
	int flags = 0;
	int optsize;
	int error;

	if (ipopt->kind == ARS_IPOPT_END || ipopt->kind == ARS_IPOPT_NOOP)
		optsize = 1;
	else
		optsize = ipopt->len;

	/* Avoid infinite loop with broken packets */
	if (optsize == 0)
		optsize = 1;

	/* pkt->aux was set by ars_split_ip, or by ars_split_ipopt itself */
	size = MIN(size, pkt->aux);
	if (size == 0) {
		*len = 0;
		*state = ARS_SPLIT_GET_DATA;
		return -ARS_OK;
	}

	if (size < optsize) {
		flags |= ARS_SPLIT_FTRUNC;
		optsize = size;
	}

	pkt->aux -= optsize;
	error = ars_add_generic(pkt, optsize, ARS_TYPE_IPOPT);
	if (error != -ARS_OK)
		return error;
	memcpy(pkt->p_layer[pkt->p_layer_nr].l_data, ipopt, optsize);
	pkt->p_layer_nr++;
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);

	*len = optsize;

	if (pkt->aux > 0) {
		*state = ARS_SPLIT_GET_IPOPT;
	} else {
		ars_ip_next_state(pkt->aux_ipproto, state);
	}
	return -ARS_OK;
}

int ars_split_icmp(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_icmphdr *icmp = packet, *newicmp;
	int flags = 0;
	int icmpsize = ARS_ICMPHDR_SIZE;

	/* Check for bad header size and checksum */
	if (size < icmpsize) {
		flags |= ARS_SPLIT_FTRUNC;
		icmpsize = size;
	}
	else if (ars_check_icmp_cksum(icmp, size) == 0)
		flags |= ARS_SPLIT_FBADCKSUM;

	if ((newicmp = ars_add_icmphdr(pkt, 0)) == NULL)
		return -ARS_NOMEM;
	memcpy(newicmp, icmp, icmpsize);
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);

	*len = icmpsize;

	if (flags & ARS_SPLIT_FTRUNC) {
		*state = ARS_SPLIT_GET_DATA;
		return -ARS_OK;
	}

	switch(icmp->type) {
	case ARS_ICMP_ECHO:
	case ARS_ICMP_ECHOREPLY:
	case ARS_ICMP_TIMESTAMP:
	case ARS_ICMP_TIMESTAMPREPLY:
	case ARS_ICMP_INFO_REQUEST:
	case ARS_ICMP_INFO_REPLY:
		*state = ARS_SPLIT_GET_DATA;
		break;
	default:
		*state = ARS_SPLIT_GET_IP;
		break;
	}
	return -ARS_OK;
}

int ars_split_data(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	void *newdata;

	if ((newdata = ars_add_data(pkt, size)) == NULL)
		return -ARS_NOMEM;
	memcpy(newdata, packet, size);

	*len = size;

	*state = ARS_SPLIT_DONE;
	return -ARS_OK;
}

int ars_split_udp(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_udphdr *udp = packet, *newudp;
	int flags = 0;
	int udpsize = ARS_UDPHDR_SIZE;
	int error;
	u_int16_t udpcksum;

	/* XXX hack, we need to add a temp unusual layer (UDP+UDP_DATA) to
	 * use the ars_udptcp_cksum() function. */

	/* --- HACK START --- */
	error = ars_add_generic(pkt, size, ARS_TYPE_UDP);
	if (error != -ARS_OK)
		return error;
	newudp = pkt->p_layer[pkt->p_layer_nr].l_data;
	memcpy(newudp, udp, size);
	newudp->uh_sum = 0;
	error = ars_udptcp_cksum(pkt, pkt->p_layer_nr, &udpcksum);
	if (error != ARS_OK) {
		printf("---ERROR DOING CHECKSUM\n");
		pkt->p_layer_nr++; /* just to be sane */
		return error;
	}
	error = ars_remove_layer(pkt, pkt->p_layer_nr);
	if (error != ARS_OK)
		return error;
	/* --- HACK END --- */

	/* Check for bad header size and checksum */
	if (size < udpsize) {
		flags |= ARS_SPLIT_FTRUNC;
		udpsize = size;
	}
	else if (udp->uh_sum != udpcksum)
		flags |= ARS_SPLIT_FBADCKSUM;

	if ((newudp = ars_add_udphdr(pkt, 0)) == NULL)
		return -ARS_NOMEM;
	memcpy(newudp, udp, udpsize);
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);

	*len = udpsize;
	*state = ARS_SPLIT_GET_DATA;
	return -ARS_OK;
}

int ars_split_tcp(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_tcphdr *tcp = packet, *newtcp;
	int flags = 0;
	int tcpsize = tcp->th_off << 2; /* FIXME: may access random memory */
	int error;
	u_int16_t tcpcksum;

	/* XXX hack, we need to add a temp unusual layer (TCP+TCP_DATA) to
	 * use the ars_udptcp_cksum() function. */

	/* --- HACK START --- */
	error = ars_add_generic(pkt, size, ARS_TYPE_TCP);
	if (error != -ARS_OK)
		return error;
	newtcp = pkt->p_layer[pkt->p_layer_nr].l_data;
	memcpy(newtcp, tcp, size);
	newtcp->th_sum = 0;
	error = ars_udptcp_cksum(pkt, pkt->p_layer_nr, &tcpcksum);
	if (error != ARS_OK) {
		pkt->p_layer_nr++; /* just to be sane */
		return error;
	}
	error = ars_remove_layer(pkt, pkt->p_layer_nr);
	if (error != ARS_OK)
		return error;
	/* --- HACK END --- */

	/* Check for bad header size and checksum */
	if (size < tcpsize) {
		flags |= ARS_SPLIT_FTRUNC;
		tcpsize = size;
	}
	else if (tcp->th_sum != tcpcksum)
		flags |= ARS_SPLIT_FBADCKSUM;

	tcpsize = MIN(tcpsize, 20);

	if ((newtcp = ars_add_tcphdr(pkt, 0)) == NULL)
		return -ARS_NOMEM;
	memcpy(newtcp, tcp, tcpsize);
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);

	*len = tcpsize;
	if (tcp->th_off > 5) {
		*state = ARS_SPLIT_GET_TCPOPT;
		pkt->aux = (tcp->th_off - 5) << 2;
	} else {
		*state = ARS_SPLIT_GET_DATA;
	}
	return -ARS_OK;
}

int ars_split_tcpopt(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_tcpopt *tcpopt = packet;
	int flags = 0;
	int optsize;
	int error;

	if (tcpopt->kind == ARS_TCPOPT_EOL || tcpopt->kind == ARS_TCPOPT_NOP ||
	    tcpopt->kind == ARS_TCPOPT_SACK_PERM)
		optsize = 1;
	else
		optsize = tcpopt->len;

	/* Avoid infinite loop with broken packets */
	if (optsize == 0)
		optsize = 1;

	/* pkt->aux was set by ars_split_tcp, or by ars_split_tcpopt itself */
	size = MIN(size, pkt->aux);
	if (size == 0) {
		*len = 0;
		*state = ARS_SPLIT_GET_DATA;
		return -ARS_OK;
	}

	if (size < optsize) {
		flags |= ARS_SPLIT_FTRUNC;
		optsize = size;
	}

	pkt->aux -= optsize;
	error = ars_add_generic(pkt, optsize, ARS_TYPE_TCPOPT);
	if (error != -ARS_OK)
		return error;
	memcpy(pkt->p_layer[pkt->p_layer_nr].l_data, tcpopt, optsize);
	pkt->p_layer_nr++;
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);

	*len = optsize;

	if (pkt->aux > 0)
		*state = ARS_SPLIT_GET_TCPOPT;
	else
		*state = ARS_SPLIT_GET_DATA;

	return -ARS_OK;
}

/* XXX: check for valid IGRP checksum */
int ars_split_igrp(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_igrphdr *igrp = packet;
	int flags = 0, igrpsize = sizeof(*igrp);
	int error;

	if (size < sizeof(*igrp)) {
		flags |= ARS_SPLIT_FTRUNC;
		igrpsize = size;
	}
	error = ars_add_generic(pkt, sizeof(*igrp), ARS_TYPE_IGRP);
	if (error != -ARS_OK)
		return error;
	memcpy(pkt->p_layer[pkt->p_layer_nr].l_data, igrp, igrpsize);
	pkt->p_layer_nr++;
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);
	*len = igrpsize;
	*state = ARS_SPLIT_GET_IGRPENTRY;
	return -ARS_OK;
}

int ars_split_igrpentry(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_igrpentry *entry = packet;
	int flags = 0, entrysize = sizeof(*entry);
	int error;

	if (size < sizeof(*entry)) {
		flags |= ARS_SPLIT_FTRUNC;
		entrysize = size;
	}
	error = ars_add_generic(pkt, sizeof(*entry), ARS_TYPE_IGRPENTRY);
	if (error != -ARS_OK)
		return error;
	memcpy(pkt->p_layer[pkt->p_layer_nr].l_data, entry, entrysize);
	pkt->p_layer_nr++;
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);
	*len = entrysize;
	*state = ARS_SPLIT_GET_IGRPENTRY;
	return -ARS_OK;
}
