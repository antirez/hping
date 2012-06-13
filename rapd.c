/* rapd.c -- Reverse APD, from ARS packet to APD string description.
 * Copyright (C) 2003 Salvatore Sanfilippo
 * All rights reserved. */

/* $Id: rapd.c,v 1.7 2004/04/10 00:45:11 antirez Exp $ */

#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>

#include "ars.h"

void trimlastchar(char *s)
{
	int len = strlen(s);
	s[len-1] = '\0';
}

int ars_d_from_ars(char *dest, size_t len, struct ars_packet *pkt)
{
	int j, err;
	struct adbuf buf;

	if (len <= 0)
		return -ARS_OK;
	if (adbuf_init(&buf))
		return -ARS_NOMEM;
	for (j = 0; j < pkt->p_layer_nr; j++) {
		__D(printf("ReverseAPD-ing layer %d\n", j);)
		/* Skip NULL compilers */
		if (ars_linfo[pkt->p_layer[j].l_type].li_rapd != NULL) {
			/* Call the layer to string converter */
			err = ars_linfo[pkt->p_layer[j].l_type].li_rapd(&buf, pkt, j);
			if (err != -ARS_OK) {
				adbuf_free(&buf);
				return err;
			}
		}
	}
	adbuf_rtrim(&buf, 1);
	strlcpy(dest, adbuf_ptr(&buf), len);
	adbuf_free(&buf);
	return -ARS_OK;
}

/* layer rapd methods */
int ars_rapd_ip(struct adbuf *dest, struct ars_packet *pkt, int layer)
{
	struct ars_iphdr *ip = pkt->p_layer[layer].l_data;
	struct ars_iphdr *defip = pkt->p_default[pkt->p_layer[layer].l_type];
	adbuf_printf(dest, "ip(");
	if (!defip || ip->ihl != defip->ihl)
		adbuf_printf(dest, "ihl=0x%1x,", ip->ihl);
	if (!defip || ip->version != defip->version)
		adbuf_printf(dest, "ver=0x%1x,", ip->version);
	if (!defip || ip->tos != defip->tos)
		adbuf_printf(dest, "tos=0x%02x,", ip->tos);
	adbuf_printf(dest, "totlen=%u,", ntohs(ip->tot_len));
	if (!defip || ip->id != defip->id)
		adbuf_printf(dest, "id=%u,", ntohs(ip->id));
	adbuf_printf(dest, "fragoff=%u,",
			(ntohs(ip->frag_off) & 0x1FFF) << 3);
	if (!defip ||
	    (ip->frag_off & ARS_IP_MF) != (defip->frag_off & ARS_IP_MF))
		adbuf_printf(dest, "mf=%d,",
				(htons(ip->frag_off) & ARS_IP_MF) != 0);
	if (!defip ||
	    (ip->frag_off & ARS_IP_DF) != (defip->frag_off & ARS_IP_DF))
		adbuf_printf(dest, "df=%d,",
				(htons(ip->frag_off) & ARS_IP_DF) != 0);
	if (!defip ||
	    (ip->frag_off & ARS_IP_RF) != (defip->frag_off & ARS_IP_RF))
		adbuf_printf(dest, "rf=%d,",
				(htons(ip->frag_off) & ARS_IP_RF) != 0);
	if (!defip || ip->ttl != defip->ttl)
		adbuf_printf(dest, "ttl=%u,", ip->ttl);
	/* TODO: the 'proto' field may not be added if the protocl
	 * that follows this layer looks as specified. */
	adbuf_printf(dest, "proto=%u,", ip->protocol);
	adbuf_printf(dest, "cksum=0x%04x,", ip->check);
	{
		unsigned char *x = (unsigned char*) &ip->saddr;
		adbuf_printf(dest, "saddr=%u.%u.%u.%u,",
				x[0], x[1], x[2], x[3]);
		x = (unsigned char*) &ip->daddr;
		adbuf_printf(dest, "daddr=%u.%u.%u.%u",
				x[0], x[1], x[2], x[3]);
	}
	adbuf_printf(dest, ")+");
	return -ARS_OK;
}

int ars_rapd_ipopt(struct adbuf *dest, struct ars_packet *pkt, int layer)
{
	struct ars_ipopt ipopt;
	int len = pkt->p_layer[layer].l_size;
	unsigned char *optp = pkt->p_layer[layer].l_data;
	int optlen, i;

	/* ip options may not be naturally aligned */
	memcpy(&ipopt, pkt->p_layer[layer].l_data, len);
	optlen = ipopt.len;

	switch(ipopt.kind) {
	case ARS_IPOPT_EOL:
		adbuf_printf(dest, "ip.eol()+");
		break;
	case ARS_IPOPT_NOP:
		adbuf_printf(dest, "ip.nop()+");
		break;
	case ARS_IPOPT_RR:
	case ARS_IPOPT_LSRR:
	case ARS_IPOPT_SSRR:
		{
			int ptr = 4;
			char *optname = "";

			switch(ipopt.kind) {
			case ARS_IPOPT_RR: optname="rr"; break;
			case ARS_IPOPT_LSRR: optname="lsrr"; break;
			case ARS_IPOPT_SSRR: optname="ssrr"; break;
			}
			adbuf_printf(dest, "ip.%s(ptr=%u,data=",
					optname, ipopt.un.rr.ptr);
			while(1) {
				unsigned char *x;

				if (ptr > 37 ||
				    ptr > (optlen-3))
					break;
				x = optp + ptr - 1;
				adbuf_printf(dest, "%u.%u.%u.%u/",
						x[0],x[1],x[2],x[3]);
				ptr += 4;
			}
			if (ptr > 4)
				adbuf_rtrim(dest, 1);
			adbuf_printf(dest, ")+");
		}
		break;
	case ARS_IPOPT_TIMESTAMP:
		{
			int ptr = 5;
			int overflow = (ipopt.un.ts.flags & 0xF0)>>4;
			int flags = ipopt.un.ts.flags & 0xF;
			char *strflags;
			adbuf_printf(dest, "ip.ts(ptr=%u,", ipopt.un.ts.ptr);
			switch(flags) {
			case ARS_IPOPT_TS_TSONLY: strflags="tsonly"; break;
			case ARS_IPOPT_TS_TSANDADDR: strflags="tsandaddr"; break;
			case ARS_IPOPT_TS_PRESPEC: strflags="prespec"; break;
			default: strflags=NULL; break;
			}
			if (strflags) {
				adbuf_printf(dest, "flags=%s,", strflags);
			} else {
				adbuf_printf(dest, "flags=%u,", flags);
			}
			adbuf_printf(dest, "overflow=%u,data=", overflow);
			while(1) {
				unsigned char *x;
				__u32 ts;

				if (ptr > 37 ||
				    ptr > (optlen-4))
					break;
				if (flags != ARS_IPOPT_TS_TSANDADDR &&
				    flags != ARS_IPOPT_TS_PRESPEC) {
					memcpy(&ts, optp+ptr-1, 4);
					ts = ntohl(ts);
					adbuf_printf(dest, "%u/", ts);
					ptr += 4;
				} else {
					x = optp + ptr - 1;
					memcpy(&ts, x+4, 4);
					adbuf_printf(dest, "%u@%u.%u.%u.%u/",
							ts,x[0],x[1],x[2],x[3]);
					ptr += 8;
				}
			}
			if (ptr > 5)
				adbuf_rtrim(dest, 1);
			adbuf_printf(dest, ")+");
		}
		break;
	default:
		adbuf_printf(dest, "ip.unknown(hex=");
		for (i = 0; i < optlen; i++) {
			adbuf_printf(dest, "0x%02x", optp[i]);
		}
		adbuf_printf(dest, ")+");
		break;
	}
	return -ARS_OK;
}

int ars_rapd_icmp(struct adbuf *dest, struct ars_packet *pkt, int layer)
{
	struct ars_icmphdr *icmp = pkt->p_layer[layer].l_data;

	adbuf_printf(dest, "icmp(");
	adbuf_printf(dest, "type=%u,", icmp->type);
	adbuf_printf(dest, "code=%u,", icmp->code);
	if (icmp->type == ARS_ICMP_DEST_UNREACH ||
	    icmp->type == ARS_ICMP_TIME_EXCEEDED ||
	    icmp->type == ARS_ICMP_PARAMETERPROB ||
	    icmp->type == ARS_ICMP_SOURCE_QUENCH)
	{
		adbuf_printf(dest, "unused=%lu,", (unsigned long)
				ntohl(icmp->un.gateway));
	}
	if (icmp->type == ARS_ICMP_ECHOREPLY ||
	    icmp->type == ARS_ICMP_ECHO ||
	    icmp->type == ARS_ICMP_TIMESTAMP ||
	    icmp->type == ARS_ICMP_TIMESTAMPREPLY ||
	    icmp->type == ARS_ICMP_INFO_REQUEST ||
	    icmp->type == ARS_ICMP_INFO_REPLY)
	{
		adbuf_printf(dest, "id=%u,", ntohs(icmp->un.echo.id));
		adbuf_printf(dest, "seq=%u,", ntohs(icmp->un.echo.sequence));
	}
	if (icmp->type == ARS_ICMP_REDIRECT) {
		unsigned char x[4];
		memcpy(x, &icmp->un.gateway, 4);
		adbuf_printf(dest, "gw=%u.%u.%u.%u,",
				x[0], x[1], x[2], x[3]);
	}
	adbuf_rtrim(dest, 1);
	adbuf_printf(dest, ")+");
	return -ARS_OK;
}

int ars_rapd_udp(struct adbuf *dest, struct ars_packet *pkt, int layer)
{
	struct ars_udphdr *udp = pkt->p_layer[layer].l_data;
	//struct ars_udphdr *defudp = pkt->p_default[pkt->p_layer[layer].l_type];
	adbuf_printf(dest, "udp(");
	adbuf_printf(dest, "sport=%u,", ntohs(udp->uh_sport));
	adbuf_printf(dest, "dport=%u,", ntohs(udp->uh_dport));
	adbuf_printf(dest, "len=%u,", ntohs(udp->uh_ulen));
	adbuf_printf(dest, "cksum=0x%04x", ntohs(udp->uh_sum));
	adbuf_printf(dest, ")+");
	return -ARS_OK;
}

int ars_rapd_tcp(struct adbuf *dest, struct ars_packet *pkt, int layer)
{
	struct ars_tcphdr *tcp = pkt->p_layer[layer].l_data;
	struct ars_tcphdr *deftcp = pkt->p_default[pkt->p_layer[layer].l_type];
	adbuf_printf(dest, "tcp(");
	adbuf_printf(dest, "sport=%u,", ntohs(tcp->th_sport));
	adbuf_printf(dest, "dport=%u,", ntohs(tcp->th_dport));
	adbuf_printf(dest, "seq=%lu,", ntohl(tcp->th_seq));
	adbuf_printf(dest, "ack=%lu,", ntohl(tcp->th_ack));
	if (!deftcp || tcp->th_x2 != deftcp->th_x2)
		adbuf_printf(dest, "x2=0x%1x,", tcp->th_x2);
	if (!deftcp || tcp->th_off != deftcp->th_off)
		adbuf_printf(dest, "off=%u,", tcp->th_off);
	adbuf_printf(dest, "flags=");
	if (tcp->th_flags & ARS_TCP_TH_FIN) adbuf_printf(dest, "f");
	if (tcp->th_flags & ARS_TCP_TH_SYN) adbuf_printf(dest, "s");
	if (tcp->th_flags & ARS_TCP_TH_RST) adbuf_printf(dest, "r");
	if (tcp->th_flags & ARS_TCP_TH_PUSH) adbuf_printf(dest, "p");
	if (tcp->th_flags & ARS_TCP_TH_ACK) adbuf_printf(dest, "a");
	if (tcp->th_flags & ARS_TCP_TH_URG) adbuf_printf(dest, "u");
	if (tcp->th_flags & ARS_TCP_TH_X) adbuf_printf(dest, "x");
	if (tcp->th_flags & ARS_TCP_TH_Y) adbuf_printf(dest, "y");
	adbuf_printf(dest, ",");
	adbuf_printf(dest, "win=%u,", ntohs(tcp->th_win));
	adbuf_printf(dest, "cksum=0x%04x,", ntohs(tcp->th_sum));
	if (!deftcp || tcp->th_urp != deftcp->th_urp)
		adbuf_printf(dest, "urp=%u,", ntohs(tcp->th_urp));
	adbuf_rtrim(dest, 1);
	adbuf_printf(dest, ")+");
	return -ARS_OK;
}

int ars_rapd_tcpopt(struct adbuf *dest, struct ars_packet *pkt, int layer)
{
	struct ars_tcpopt tcpopt;
	int len = pkt->p_layer[layer].l_size;
	unsigned char *optp = pkt->p_layer[layer].l_data;
	int optlen, i;

	/* tcp options may not be naturally aligned */
	memcpy(&tcpopt, pkt->p_layer[layer].l_data, len);
	optlen = tcpopt.len;

	switch(tcpopt.kind) {
	case ARS_TCPOPT_EOL:
		adbuf_printf(dest, "tcp.eol()+");
		break;
	case ARS_TCPOPT_NOP:
		adbuf_printf(dest, "tcp.nop()+");
		break;
	case ARS_TCPOPT_MAXSEG:
		adbuf_printf(dest, "tcp.mss(size=%u)+",
				ntohs(tcpopt.un.mss.size));
		break;
	case ARS_TCPOPT_WINDOW:
		adbuf_printf(dest, "tcp.wscale(shift=%u)+",
				tcpopt.un.win.shift);
		break;
	case ARS_TCPOPT_SACK_PERM:
		adbuf_printf(dest, "tcp.sackperm()+");
		break;
	case ARS_TCPOPT_SACK:
		adbuf_printf(dest, "tcp.sack(blocks=");
		{
			int blocks = (optlen-2)/8;
			for (i = 0; i < blocks; i++) {
				u_int32_t s_orig, s_size;

				memcpy(&s_orig, tcpopt.un.sack[i].origin, 4);
				memcpy(&s_size, tcpopt.un.sack[i].size, 4);
				adbuf_printf(dest, "%lu-%lu",
					ntohl(s_orig),
					ntohl(s_size));
				if ((i+1) != blocks)
					adbuf_addchar(dest, '/');
			}
		}
		adbuf_printf(dest, ")+");
		break;
	case ARS_TCPOPT_ECHOREQUEST:
		{
			__u32 info;
			memcpy(&info, tcpopt.un.echo.info, 4);
			adbuf_printf(dest, "tcp.echoreq(info=%lu)+",
					(unsigned long) ntohl(info));
		}
		break;
	case ARS_TCPOPT_ECHOREPLY:
		{
			__u32 info;
			memcpy(&info, tcpopt.un.echo.info, 4);
			adbuf_printf(dest, "tcp.echoreply(info=%lu)+",
					(unsigned long) ntohl(info));
		}
		break;
	case ARS_TCPOPT_TIMESTAMP:
		{
			__u32 tsval, tsecr;
			memcpy(&tsval, tcpopt.un.timestamp.tsval, 4);
			memcpy(&tsecr, tcpopt.un.timestamp.tsecr, 4);
			adbuf_printf(dest, "tcp.timestamp(val=%lu,ecr=%lu)+",
				(unsigned long) ntohl(tsval),
				(unsigned long) ntohl(tsecr));
		}
		break;
	default:
		adbuf_printf(dest, "tcp.unknown(hex=");
		for (i = 0; i < optlen; i++) {
			adbuf_printf(dest, "%02x", optp[i]);
		}
		adbuf_printf(dest, ")+");
		break;
	}
	return -ARS_OK;
}

int ars_rapd_igrp(struct adbuf *dest, struct ars_packet *pkt, int layer)
{
	struct ars_igrphdr *igrp = pkt->p_layer[layer].l_data;

	adbuf_printf(dest, "igrp(");
	adbuf_printf(dest, "version=%u,", igrp->version);
	if (igrp->opcode == ARS_IGRP_OPCODE_UPDATE) {
		adbuf_printf(dest, "opcode=update,", igrp->opcode);
	} else if (igrp->opcode == ARS_IGRP_OPCODE_REQUEST) {
		adbuf_printf(dest, "opcode=request,", igrp->opcode);
	} else {
		adbuf_printf(dest, "opcode=%u,", igrp->opcode);
	}
	adbuf_printf(dest, "edition=%u,", igrp->edition);
	adbuf_printf(dest, "autosys=%u,", htons(igrp->autosys));
	adbuf_printf(dest, "interior=%u,", htons(igrp->interior));
	adbuf_printf(dest, "system=%u,", htons(igrp->system));
	adbuf_printf(dest, "exterior=%u,", htons(igrp->exterior));
	adbuf_printf(dest, "cksum=0x%04x", ntohs(igrp->checksum));
	adbuf_printf(dest, ")+");
	return -ARS_OK;
}

static u_int32_t get_net_int24(void *ptr)
{
	unsigned char *x = (unsigned char*)ptr;
	u_int32_t u;

	u = x[0] <<16 | x[1] << 8 | x[2];
	return u;
}

int ars_rapd_igrpentry(struct adbuf *dest, struct ars_packet *pkt, int layer)
{
	struct ars_igrpentry *entry = pkt->p_layer[layer].l_data;
	unsigned char *x = (unsigned char*) entry->destination;

	adbuf_printf(dest, "igrp.entry(");
	adbuf_printf(dest, "dest=%u.%u.%u,", x[0], x[1], x[2]);
	adbuf_printf(dest, "delay=%u,", get_net_int24(entry->delay));
	adbuf_printf(dest, "bandwidth=%u,", get_net_int24(entry->bandwidth));
	adbuf_printf(dest, "mtu=%u,", entry->mtu[0] << 8 | entry->mtu[1]);
	adbuf_printf(dest, "reliability=%u,", entry->reliability);
	adbuf_printf(dest, "load=%u,", entry->load);
	adbuf_printf(dest, "hopcount=%u", entry->hopcount);
	adbuf_printf(dest, ")+");
	return -ARS_OK;
}

int ars_rapd_data(struct adbuf *dest, struct ars_packet *pkt, int layer)
{
	unsigned char *data = pkt->p_layer[layer].l_data;
	int dlen = pkt->p_layer[layer].l_size, i;

	if (ars_test_option(pkt, ARS_OPT_RAPD_HEXDATA)) {
		adbuf_printf(dest, "data(hex=");
		for (i = 0; i < dlen; i++) {
			adbuf_printf(dest, "%02x", data[i]);
		}
		adbuf_printf(dest, ")+");
	} else {
		adbuf_printf(dest, "data(str=");
		for (i = 0; i < dlen; i++) {
			/* escape non-printable chars and chars
			 * having special meanings in APD packets. */
			if (isgraph(data[i]) &&
			    data[i] != '(' &&
			    data[i] != ')' &&
			    data[i] != '+' &&
			    data[i] != ',' &&
			    data[i] != '=')
				adbuf_printf(dest, "%c", data[i]);
			else
				adbuf_printf(dest, "\\%02x", data[i]);
		}
		adbuf_printf(dest, ")+");
	}
	return 0;
}
