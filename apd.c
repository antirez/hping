/* Copyright (C) 2000,2001 Salvatore Sanfilippo <antirez@invece.org>
 * See the LICENSE file for more information.
 *
 * ARS Packet Description System.
 *
 * Please, prefix all the function with ars_d_ */

/* $Id: apd.c,v 1.3 2003/09/07 11:21:18 antirez Exp $ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include "ars.h"
#include "hstring.h"
#include "hex.h"

/* FIXME: parsing should use dynamic buffers to use less memory.
 * For now we support MTU up to 3000 */
#define ARS_MAX_TSIZE	(3000*4)
char *ars_d_parser(char *t, char *next, size_t size)
{
	int i = 0;

	if (size == 0 || next == NULL || *t == '\0')
		return NULL;
	size--; /* space for nul term */
	while (1) {
		/* no space for the next char */
		if (i == size) {
			next[i] = '\0';
			return t;
		}
		switch(*t) {
		case '\0':
		case '(':
		case ')':
		case ',':
		case '=':
		case '+':
			if (i == 0) {
				next[i] = *t;
				next[i+1] = '\0';
				return t+1;
			} else {
				next[i] = '\0';
				return t;
			}
		default:
			next[i++] = *t++;
			break;
		}
	}
	return NULL; /* unreached */
}

/* states */
#define ARS_G_LAYER		0
#define ARS_G_FIELD_OR_CBRACE	1
#define ARS_G_VALUE		2
#define ARS_G_OBRACE_OR_PLUS	3
#define ARS_G_CBRACE		4
#define ARS_G_COMMA_OR_CBRACE	5
#define ARS_G_LEN_OR_PLUS	6
#define ARS_G_PLUS		7
#define ARS_G_EQUAL		8

struct ars_d_keyword_info {
	char *ki_keyword;
	int ki_opt;
	void *(*ki_add) (struct ars_packet *pkt, int opt);
	int (*ki_set) (struct ars_packet *pkt, int layer, char *f, char *v);
};

#define ARS_DKINFO_SIZE		64

/* If the user specify a layer number of -1 with *set functions, the
 * last layer is selected */
#define ARS_DEF_LAYER \
do { \
	if (layer == ARS_LAST_LAYER) \
		layer = pkt->p_layer_nr - 1; \
	if (ars_valid_layer(layer) != -ARS_OK) \
		return -ARS_INVALID; \
} while(0)

#define BOGUS_SET_F(x) \
  int (x)(struct ars_packet *pkt, int layer, char *f, char *v) { return 0; }

int ars_d_set_ip(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_udp(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_tcp(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_icmp(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_data(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_ipopt_rr(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_ipopt_ts(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_ipopt_sid(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_ipopt_sec(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_ipopt_dumb(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_tcpopt_mss(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_tcpopt_wscale(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_tcpopt_sack(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_tcpopt_echo(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_tcpopt_dumb(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_igrp(struct ars_packet *pkt, int layer, char *f, char *v);
int ars_d_set_igrpentry(struct ars_packet *pkt, int layer, char *f, char *v);
BOGUS_SET_F(ars_d_set_tcpopt_ts)

struct ars_d_keyword_info ars_dkinfo[ARS_DKINFO_SIZE] = {
	/* KEYWORD	OPT		ADD function	SET function *
	 * --------------------------------------------------------- */
	{"ip",		0,		ars_add_iphdr,	ars_d_set_ip},
	{"ip.eol",	ARS_IPOPT_EOL,	ars_add_ipopt,	ars_d_set_ipopt_dumb},
	{"ip.nop",	ARS_IPOPT_NOP,	ars_add_ipopt,	ars_d_set_ipopt_dumb},
	{"ip.sec",	ARS_IPOPT_SEC,	ars_add_ipopt,	ars_d_set_ipopt_sec},
	{"ip.sid",	ARS_IPOPT_SID,	ars_add_ipopt,	ars_d_set_ipopt_sid},
	{"ip.lsrr",	ARS_IPOPT_LSRR,	ars_add_ipopt,	ars_d_set_ipopt_rr},
	{"ip.ssrr",	ARS_IPOPT_SSRR,	ars_add_ipopt,	ars_d_set_ipopt_rr},
	{"ip.rr",	ARS_IPOPT_RR,	ars_add_ipopt,	ars_d_set_ipopt_rr},
	{"ip.ts",	ARS_IPOPT_TIMESTAMP, ars_add_ipopt, ars_d_set_ipopt_ts},
	{"udp",		0,		ars_add_udphdr,	ars_d_set_udp},
	{"tcp",		0,		ars_add_tcphdr,	ars_d_set_tcp},
	{"tcp.eol",	ARS_TCPOPT_EOL,	ars_add_tcpopt,	ars_d_set_tcpopt_dumb},
	{"tcp.nop",	ARS_TCPOPT_NOP,	ars_add_tcpopt,	ars_d_set_tcpopt_dumb},
	{"tcp.mss",	ARS_TCPOPT_MAXSEG, ars_add_tcpopt, ars_d_set_tcpopt_mss},
	{"tcp.wscale", ARS_TCPOPT_WINDOW, ars_add_tcpopt, ars_d_set_tcpopt_wscale},
	{"tcp.sackperm", ARS_TCPOPT_SACK_PERM, ars_add_tcpopt, ars_d_set_tcpopt_dumb},
	{"tcp.sack", ARS_TCPOPT_SACK, ars_add_tcpopt, ars_d_set_tcpopt_sack},
	{"tcp.echo", ARS_TCPOPT_ECHOREQUEST, ars_add_tcpopt, ars_d_set_tcpopt_echo},
	{"tcp.echoreply", ARS_TCPOPT_ECHOREPLY, ars_add_tcpopt, ars_d_set_tcpopt_echo},
	{"tcp.ts",	ARS_TCPOPT_TIMESTAMP, ars_add_tcpopt, ars_d_set_tcpopt_ts},
	{"icmp",	0,		ars_add_icmphdr, ars_d_set_icmp},
	{"igrp",	0,		ars_add_igrphdr, ars_d_set_igrp},
	{"igrp.entry",	0,		ars_add_igrpentry, ars_d_set_igrpentry},
	{"data",	0,		ars_add_data,	ars_d_set_data},
	{NULL, 0, NULL, NULL} /* nul term */
};

struct ars_d_keyword_info *ars_get_keyword_by_name(char *name)
{
	struct ars_d_keyword_info *k = ars_dkinfo;

	while (k->ki_keyword) {
		if (strcasecmp(k->ki_keyword, name) == 0)
			return k;
		k++;
	}
	return NULL;
}

int ars_d_setlayer_size(struct ars_packet *pkt, int layer, char *size)
{
	size_t newsize;

	ARS_DEF_LAYER;
	newsize = ars_atou(size);
	if (newsize < 1 || newsize > pkt->p_layer[layer].l_size) {
		ars_set_error(pkt, "Invalid layer size in description");
		return -ARS_INVALID;
	}
	pkt->p_layer[layer].l_size = newsize;

	__D(printf("Setting the layer to size %s\n", size);)
	return -ARS_OK;
}

int ars_d_set_ip(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_iphdr *ip;

	ARS_DEF_LAYER;
	ip = pkt->p_layer[layer].l_data;

	if (strcasecmp(f, "saddr") == 0) {
		return ars_resolve(pkt, &ip->saddr, v);
	} else if (strcasecmp(f, "daddr") == 0) {
		return ars_resolve(pkt, &ip->daddr, v);
	} else if (strcasecmp(f, "ihl") == 0) {
		ip->ihl = ars_atou(v);
		pkt->p_layer[layer].l_flags |= ARS_TAKE_IP_HDRLEN;
	} else if (strcasecmp(f, "ver") == 0) {
		ip->version = ars_atou(v);
		pkt->p_layer[layer].l_flags |= ARS_TAKE_IP_VERSION;
	} else if (strcasecmp(f, "tos") == 0) {
		ip->tos = ars_atou(v);
	} else if (strcasecmp(f, "totlen") == 0) {
		ip->tot_len = htons(ars_atou(v));
		pkt->p_layer[layer].l_flags |= ARS_TAKE_IP_TOTLEN;
	} else if (strcasecmp(f, "id") == 0) {
		ip->id = htons(ars_atou(v));
	} else if (strcasecmp(f, "fragoff") == 0) {
		ip->frag_off = ip->frag_off & 0xE000;
		ip->frag_off |= htons(ars_atou(v) >> 3);
	} else if (strcasecmp(f, "mf") == 0) {
		if (ars_atou(v) == 0)
			ip->frag_off &= htons(~ARS_IP_MF);
		else
			ip->frag_off |= htons(ARS_IP_MF);
	} else if (strcasecmp(f, "df") == 0) {
		if (ars_atou(v) == 0)
			ip->frag_off &= htons(~ARS_IP_DF);
		else
			ip->frag_off |= htons(ARS_IP_DF);
	} else if (strcasecmp(f, "rf") == 0) {
		if (ars_atou(v) == 0)
			ip->frag_off &= htons((u_int16_t)~ARS_IP_RF);
		else
			ip->frag_off |= htons(ARS_IP_RF);
	} else if (strcasecmp(f, "ttl") == 0) {
		ip->ttl = ars_atou(v);
	} else if (strcasecmp(f, "proto") == 0) {
		if (!strcasecmp(v, "icmp")) {
			ip->protocol = ARS_IPPROTO_ICMP;
		} else if (!strcasecmp(v, "udp")) {
			ip->protocol = ARS_IPPROTO_UDP;
		} else if (!strcasecmp(v, "tcp")) {
			ip->protocol = ARS_IPPROTO_TCP;
		} else {
			ip->protocol = ars_atou(v);
		}
		pkt->p_layer[layer].l_flags |= ARS_TAKE_IP_PROTOCOL;
	} else if (strcasecmp(f, "cksum") == 0) {
		ip->check = htons(ars_atou(v));
		pkt->p_layer[layer].l_flags |= ARS_TAKE_IP_CKSUM;
	} else {
		ars_set_error(pkt, "Invalid field for IP layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

/* Note: for all the variable-length ip options the allocated layer data
 * length is always as big as possible (40 bytes), so set_ipopt_rr() and
 * other similar functions don't need to check if there is enough room.
 * Of course functions shoult still check to not overflow over the 40
 * bytes, but this makes very little sense. */
#define IPOPTRR_MAX_ENTRIES 9
int ars_d_set_ipopt_rr(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_ipopt *ipopt;

	ARS_DEF_LAYER;
	ipopt = pkt->p_layer[layer].l_data;

	if (strcasecmp(f, "optlen") == 0) {
		ipopt->len = ars_atou(v);
	} else if (strcasecmp(f, "ptr") == 0) {
		ipopt->un.rr.ptr = ars_atou(v);
		pkt->p_layer[layer].l_flags |= ARS_TAKE_IPOPT_PTR;
	} else if (strcasecmp(f, "data") == 0) {
		char *addrv[IPOPTRR_MAX_ENTRIES];
		int vlen = strlen(v), num, i;
		char *vcopy = alloca(vlen+1);
		unsigned char *data = pkt->p_layer[layer].l_data;

		memcpy(vcopy, v, vlen+1);
		num = strftok("/", vcopy, addrv, IPOPTRR_MAX_ENTRIES);
		for (i = 0; i < num; i++) {
			__u32 addr;
			int err;

			err = ars_resolve(pkt, &addr, addrv[i]);
			if (err != -ARS_OK)
				return err;
			memcpy(data+3+(i*4), &addr, 4);
		}
		if (ARS_DONTTAKE(pkt->p_layer[layer].l_flags,
					ARS_TAKE_IPOPT_PTR))
		{
			/* For the record route option the default ptr
			 * is at the end of the specified entries */
			if (ipopt->kind == ARS_IPOPT_RR) {
				ipopt->un.rr.ptr = 4+(num*4);
			} else {
			/* For SSRR and LSRR is set at the start
			 * if not otherwise specified. */
				ipopt->un.rr.ptr = 4;
			}
		}
	} else {
		ars_set_error(pkt, "Invalid field for IP.RR layer: '%s'", f);
		return -ARS_INVALID;
	}

	return -ARS_OK;
}

#define IPOPTTS_MAX_ENTRIES 9
int ars_d_set_ipopt_ts(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_ipopt *ipopt;
	int flags, overflow;

	ARS_DEF_LAYER;
	ipopt = pkt->p_layer[layer].l_data;
	overflow = (ipopt->un.ts.flags & 0xF0) >> 4;
	flags = ipopt->un.ts.flags & 0xF;

	if (strcasecmp(f, "optlen") == 0) {
		ipopt->len = ars_atou(v);
	} else if (strcasecmp(f, "ptr") == 0) {
		ipopt->un.rr.ptr = ars_atou(v);
		pkt->p_layer[layer].l_flags |= ARS_TAKE_IPOPT_PTR;
	} else if (strcasecmp(f, "flags") == 0) {
		if (strisnum(v)) {
			flags = ars_atou(v) & 0xF;
		} else {
			if (!strcasecmp(v, "tsonly"))
				flags = ARS_IPOPT_TS_TSONLY;
			else if (!strcasecmp(v, "tsandaddr"))
				flags = ARS_IPOPT_TS_TSANDADDR;
			else if (!strcasecmp(v, "prespec"))
				flags = ARS_IPOPT_TS_PRESPEC;
			else {
				ars_set_error(pkt, "Invalid symbol for ip.ts flags: '%s' (use: tsonly, tsandaddr, prespec or a numerical value)", v);
				return -ARS_INVALID;
			}
		}
		ipopt->un.ts.flags = ((overflow&0xF)<<4)|(flags&0xF);
	} else if (strcasecmp(f, "overflow") == 0) {
		overflow = ars_atou(v) & 0xF;
		ipopt->un.ts.flags = ((overflow&0xF)<<4)|(flags&0xF);
	} else if (strcasecmp(f, "data") == 0) {
		char *addrv[IPOPTTS_MAX_ENTRIES];
		int vlen = strlen(v), num, i;
		char *vcopy = alloca(vlen+1);
		unsigned char *data = pkt->p_layer[layer].l_data;

		memcpy(vcopy, v, vlen+1);
		num = strftok("/", vcopy, addrv, IPOPTTS_MAX_ENTRIES);
		for (i = 0; i < num; i++) {
			__u32 addr, ts;
			int err;
			char *p;

			p = strchr(addrv[i], '@');
			if (p) {
				if (flags == ARS_IPOPT_TS_TSONLY) {
					ars_set_error(pkt, "Gateway specified but ip.ts flags set to 'tsonly'. (Try flags=tsandaddr,data=...)");
					return -ARS_INVALID;
				}
				*p = '\0';
				p++;
				err = ars_resolve(pkt, &addr, p);
				if (err != -ARS_OK)
					return err;
				ts = ars_atou(addrv[i]);
				ts = htonl(ts);
				if (i < 4) {
					memcpy(data+4+(i*8), &addr, 4);
					memcpy(data+8+(i*8), &ts, 4);
				};
			} else {
				if (flags == ARS_IPOPT_TS_TSANDADDR ||
				    flags == ARS_IPOPT_TS_PRESPEC) {
					ars_set_error(pkt, "Gateway not specified in data for ip.ts, but flags set to 'tsandaddr' or 'prespec'. (Try flags=tsonly)");
					return -ARS_INVALID;
				}
				ts = ars_atou(addrv[i]);
				ts = htonl(ts);
				memcpy(data+4+(i*4), &ts, 4);
			}
		}
		if (ARS_DONTTAKE(pkt->p_layer[layer].l_flags,
					ARS_TAKE_IPOPT_PTR))
		{
			if (flags == ARS_IPOPT_TS_TSANDADDR ||
			    flags == ARS_IPOPT_TS_PRESPEC) {
				ipopt->un.rr.ptr = 5+(num*8);
			} else {
				ipopt->un.rr.ptr = 5+(num*4);
			}
		}
	} else {
		ars_set_error(pkt, "Invalid field for IP.TS layer: '%s'", f);
		return -ARS_INVALID;
	}

	return -ARS_OK;
}

int ars_d_set_ipopt_sid(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_ipopt *ipopt;

	ARS_DEF_LAYER;
	ipopt = pkt->p_layer[layer].l_data;
	if (strcasecmp(f, "optlen") == 0) {
		ipopt->len = ars_atou(v);
	} else if (strcasecmp(f, "sid") == 0) {
		ipopt->un.sid.id = ars_atou(v);
	} else {
		ars_set_error(pkt, "Invalid field for IP.SID layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

int ars_d_set_ipopt_sec(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_ipopt *ipopt;

	ARS_DEF_LAYER;
	ipopt = pkt->p_layer[layer].l_data;
	if (strcasecmp(f, "optlen") == 0) {
		ipopt->len = ars_atou(v);
	} else if (strcasecmp(f, "seclev") == 0) {
		ipopt->un.sec.s = ars_atou(v);
	} else if (strcasecmp(f, "comp") == 0) {
		ipopt->un.sec.c = ars_atou(v);
	} else if (strcasecmp(f, "hrest") == 0) {
		if (strlen(v) != 4) {
			ars_set_error(pkt, "Invalid ip.sec hrest field value of '%s'(should be four hex digits, like this: ...,hrest=252A,...)", v);
			return -ARS_INVALID;
		}
		if (hextobin(&ipopt->un.sec.h, v, 4)) {
			ars_set_error(pkt, "Invalid hex value for ip.sec hex: '%s'", v);
			return -ARS_INVALID;
		}
	} else if (strcasecmp(f, "tcc") == 0) {
		if (strlen(v) != 6) {
			ars_set_error(pkt, "Invalid ip.sec tcc field value of '%s'(should be six hex digits, like this: ...,tcc=252A27,...)", v);
			return -ARS_INVALID;
		}
		if (hextobin(&ipopt->un.sec.h, v, 6)) {
			ars_set_error(pkt, "Invalid hex value for ip.sec hex: '%s'", v);
			return -ARS_INVALID;
		}
	} else {
		ars_set_error(pkt, "Invalid field for IP.SEC layer: '%s'", f);
		return -ARS_INVALID;
	}

	return -ARS_OK;
}

int ars_d_set_ipopt_dumb(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_ipopt *ipopt;

	ARS_DEF_LAYER;
	ipopt = pkt->p_layer[layer].l_data;
	if (strcasecmp(f, "optlen") == 0) {
		ipopt->len = ars_atou(v);
	} else {
		ars_set_error(pkt, "Invalid field for IP.? layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

int ars_d_set_udp(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_udphdr *udp;

	ARS_DEF_LAYER;
	udp = pkt->p_layer[layer].l_data;

	if (strcasecmp(f, "sport") == 0) {
		udp->uh_sport = htons(ars_atou(v));
	} else if (strcasecmp(f, "dport") == 0) {
		udp->uh_dport = htons(ars_atou(v));
	} else if (strcasecmp(f, "len") == 0) {
		udp->uh_ulen = htons(ars_atou(v));
		pkt->p_layer[layer].l_flags |= ARS_TAKE_UDP_LEN;
	} else if (strcasecmp(f, "cksum") == 0) {
		udp->uh_sum = htons(ars_atou(v));
		pkt->p_layer[layer].l_flags |= ARS_TAKE_UDP_CKSUM;
	} else {
		ars_set_error(pkt, "Invalid field for UDP layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

int ars_d_set_tcp(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_tcphdr *tcp;

	ARS_DEF_LAYER;
	tcp = pkt->p_layer[layer].l_data;

	if (strcasecmp(f, "sport") == 0) {
		tcp->th_sport = htons(ars_atou(v));
	} else if (strcasecmp(f, "dport") == 0) {
		tcp->th_dport = htons(ars_atou(v));
	} else if (strcasecmp(f, "seq") == 0) {
		tcp->th_seq = htonl(ars_atou(v));
	} else if (strcasecmp(f, "ack") == 0) {
		tcp->th_ack = htonl(ars_atou(v));
	} else if (strcasecmp(f, "x2") == 0) {
		tcp->th_x2 = ars_atou(v);
	} else if (strcasecmp(f, "off") == 0) {
		tcp->th_off = ars_atou(v);
		pkt->p_layer[layer].l_flags |= ARS_TAKE_TCP_HDRLEN;
	} else if (strcasecmp(f, "flags") == 0) {
		tcp->th_flags = 0;
		if (strchr(v, 'f') || strchr(v, 'F'))
			tcp->th_flags |= ARS_TCP_TH_FIN;
		if (strchr(v, 's') || strchr(v, 'S'))
			tcp->th_flags |= ARS_TCP_TH_SYN;
		if (strchr(v, 'r') || strchr(v, 'R'))
			tcp->th_flags |= ARS_TCP_TH_RST;
		if (strchr(v, 'p') || strchr(v, 'P'))
			tcp->th_flags |= ARS_TCP_TH_PUSH;
		if (strchr(v, 'a') || strchr(v, 'A'))
			tcp->th_flags |= ARS_TCP_TH_ACK;
		if (strchr(v, 'u') || strchr(v, 'U'))
			tcp->th_flags |= ARS_TCP_TH_URG;
		if (strchr(v, 'x') || strchr(v, 'X'))
			tcp->th_flags |= ARS_TCP_TH_X;
		if (strchr(v, 'y') || strchr(v, 'Y'))
			tcp->th_flags |= ARS_TCP_TH_Y;
	} else if (strcasecmp(f, "win") == 0) {
		tcp->th_win = htons(ars_atou(v));
	} else if (strcasecmp(f, "cksum") == 0) {
		tcp->th_sum = htons(ars_atou(v));
		pkt->p_layer[layer].l_flags |= ARS_TAKE_TCP_CKSUM;
	} else if (strcasecmp(f, "urp") == 0) {
		tcp->th_urp = htons(ars_atou(v));
	} else {
		ars_set_error(pkt, "Invalid field for TCP layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

int ars_d_set_tcpopt_mss(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_tcpopt *tcpopt;

	ARS_DEF_LAYER;
	tcpopt = pkt->p_layer[layer].l_data;
	if (strcasecmp(f, "optlen") == 0) {
		tcpopt->len = ars_atou(v);
	} else if (strcasecmp(f, "size") == 0) {
		tcpopt->un.mss.size = htons(ars_atou(v));
	} else {
		ars_set_error(pkt, "Invalid field for TCP.MSS layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

int ars_d_set_tcpopt_wscale(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_tcpopt *tcpopt;

	ARS_DEF_LAYER;
	tcpopt = pkt->p_layer[layer].l_data;
	if (strcasecmp(f, "optlen") == 0) {
		tcpopt->len = ars_atou(v);
	} else if (strcasecmp(f, "shift") == 0) {
		tcpopt->un.win.shift = htons(ars_atou(v));
	} else {
		ars_set_error(pkt, "Invalid field for TCP.WSCALE layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

#define TCPOPTSACK_MAX_ENTRIES 4
int ars_d_set_tcpopt_sack(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_tcpopt *tcpopt;

	ARS_DEF_LAYER;
	tcpopt = pkt->p_layer[layer].l_data;
	if (strcasecmp(f, "optlen") == 0) {
		tcpopt->len = ars_atou(v);
	} else if (strcasecmp(f, "blocks") == 0) {
		char *bv[TCPOPTSACK_MAX_ENTRIES];
		int vlen = strlen(v), num, i;
		char *vcopy = alloca(vlen+1);
		unsigned char *data = pkt->p_layer[layer].l_data;

		memcpy(vcopy, v, vlen+1);
		num = strftok("/", vcopy, bv, TCPOPTSACK_MAX_ENTRIES);
		for (i = 0; i < num; i++) {
			char *p;
			__u32 s_origin, s_len;

			p = strchr(bv[i], '-');
			if (!p) {
				ars_set_error(pkt, "Invalid syntax for tcp.sack blocks: '%s' (try ...tcp.sack(blocks=123342-10/12653-50/0-0/0-0)... )");
				return -ARS_INVALID;
			}
			*p = '\0';
			p++;
			s_origin = htonl(ars_atou(bv[i]));
			s_len = htonl(ars_atou(p));
			memcpy(data+2+(i*8), &s_origin, 4);
			memcpy(data+6+(i*8), &s_len, 4);
		}
	} else {
		ars_set_error(pkt, "Invalid field for TCP.SACK layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

int ars_d_set_tcpopt_dumb(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_tcpopt *tcpopt;

	ARS_DEF_LAYER;
	tcpopt = pkt->p_layer[layer].l_data;
	if (strcasecmp(f, "optlen") == 0) {
		tcpopt->len = ars_atou(v);
	} else {
		ars_set_error(pkt, "Invalid field for TCP.? layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

int ars_d_set_tcpopt_echo(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_tcpopt *tcpopt;

	ARS_DEF_LAYER;
	tcpopt = pkt->p_layer[layer].l_data;
	if (strcasecmp(f, "optlen") == 0) {
		tcpopt->len = ars_atou(v);
	} else if (strcasecmp(f, "info") == 0) {
		u_int32_t info = htonl(ars_atou(v));
		memcpy(tcpopt->un.echo.info, &info, 4);
	} else {
		ars_set_error(pkt, "Invalid field for TCP.ECHO layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

int ars_d_set_icmp(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_icmphdr *icmp;

	ARS_DEF_LAYER;
	icmp = pkt->p_layer[layer].l_data;

	if (strcasecmp(f, "type") == 0) {
		icmp->type = ars_atou(v);
	} else if (strcasecmp(f, "code") == 0) {
		icmp->code = ars_atou(v);
	} else if (strcasecmp(f, "cksum") == 0) {
		icmp->checksum = htons(ars_atou(v));
		pkt->p_layer[layer].l_flags |= ARS_TAKE_ICMP_CKSUM;
	} else if (strcasecmp(f, "id") == 0) {
		icmp->un.echo.id = htons(ars_atou(v));
	} else if (strcasecmp(f, "seq") == 0) {
		icmp->un.echo.sequence = htons(ars_atou(v));
	} else if (strcasecmp(f, "gw") == 0) {
		return ars_resolve(pkt, &icmp->un.gateway, v);
	} else if (strcasecmp(f, "unused") == 0) {
		icmp->un.gateway = htonl(ars_atou(v));
	} else {
		ars_set_error(pkt, "Invalid field for ICMP layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

int ars_d_set_igrp(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_igrphdr *igrp;

	ARS_DEF_LAYER;
	igrp = pkt->p_layer[layer].l_data;

	if (strcasecmp(f, "version") == 0) {
		igrp->version = ars_atou(v);
	} else if (strcasecmp(f, "opcode") == 0) {
		if (strcasecmp(v, "update") == 0)
			igrp->opcode = ARS_IGRP_OPCODE_UPDATE;
		else if (strcasecmp(v, "request") == 0)
			igrp->opcode = ARS_IGRP_OPCODE_REQUEST;
		else
			igrp->opcode = ars_atou(v);
	} else if (strcasecmp(f, "cksum") == 0) {
		igrp->checksum = htons(ars_atou(v));
		pkt->p_layer[layer].l_flags |= ARS_TAKE_IGRP_CKSUM;
	} else if (strcasecmp(f, "edition") == 0) {
		igrp->edition = ars_atou(v);
	} else if (strcasecmp(f, "autosys") == 0) {
		igrp->autosys = htons(ars_atou(v));
	} else if (strcasecmp(f, "interior") == 0) {
		igrp->interior = htons(ars_atou(v));
	} else if (strcasecmp(f, "system") == 0) {
		igrp->system= htons(ars_atou(v));
	} else if (strcasecmp(f, "exterior") == 0) {
		igrp->exterior = htons(ars_atou(v));
	} else {
		ars_set_error(pkt, "Invalid field for IGRP layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

static int igrp_set_dest(unsigned char *d, char *v)
{
	int l = strlen(v);
	char *vcopy = alloca(l+1);
	char *f0, *f1, *f2;

	memcpy(vcopy, v, l+1);
	f0 = vcopy;
	if ((f1 = strchr(f0, '.')) == NULL)
		return 1;
	*f1++ = '\0';
	if ((f2 = strchr(f1, '.')) == NULL)
		return 1;
	*f2++ = '\0';
	if (!strisnum(f0) || !strisnum(f1) || !strisnum(f2))
		return 1;
	d[0] = ars_atou(f0);
	d[1] = ars_atou(f1);
	d[2] = ars_atou(f2);
	return 0;
}

static void igrp_set_uint24(void *d, char *v)
{
	__u32 t;
	unsigned char *x;

	t = htonl(ars_atou(v));
	x = (unsigned char*) &t;
	memcpy(d, x+1, 3);
}

int ars_d_set_igrpentry(struct ars_packet *pkt, int layer, char *f, char *v)
{
	struct ars_igrpentry *entry;

	ARS_DEF_LAYER;
	entry = pkt->p_layer[layer].l_data;

	if (strcasecmp(f, "dest") == 0) {
		if (igrp_set_dest(entry->destination, v)) {
			ars_set_error(pkt, "Invalid IGRP entry 'dest' field value: '%s'\n", v);
			return -ARS_INVALID;
		}
	} else if (strcasecmp(f, "delay") == 0) {
		igrp_set_uint24(entry->delay, v);
	} else if (strcasecmp(f, "bandwidth") == 0) {
		igrp_set_uint24(entry->bandwidth, v);
	} else if (strcasecmp(f, "mtu") == 0) {
		__u16 mtu = htons(ars_atou(v));
		memcpy(entry->mtu, &mtu, 2);
	} else if (strcasecmp(f, "reliability") == 0) {
		entry->reliability = ars_atou(v);
	} else if (strcasecmp(f, "load") == 0) {
		entry->load = ars_atou(v);
	} else if (strcasecmp(f, "hopcount") == 0) {
		entry->hopcount = ars_atou(v);
	} else {
		ars_set_error(pkt, "Invalid field for IGRP.ENTRY layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

int ars_push_data(struct ars_packet *pkt, int layer, void *data, size_t size)
{
	char *p;
	int old_size;

	ARS_DEF_LAYER;
	old_size = pkt->p_layer[layer].l_size;
	p = realloc(pkt->p_layer[layer].l_data, old_size + size);
	if (p == NULL)
		return -ARS_NOMEM;
	memcpy(p+old_size, data, size);
	pkt->p_layer[layer].l_data = p;
	pkt->p_layer[layer].l_size += size;
	return ARS_OK;
}

static int hextab[256];
static int hextab_initialized = 0;
static char *hexdig = "0123456789abcdef";

static char *ars_decode_hex(struct ars_packet *pkt, char *s, int *blen)
{
	int len = strlen(s), i;
	unsigned char *d, *saved;

	if (len%2) {
		ars_set_error(pkt, "Odd length of 'hex' data");
		return NULL;
	}
	*blen = len/2;
	if (!hextab_initialized) {
		memset(hextab, 255, 255);
		for (i = 0; i < 16; i++)
			hextab[(int)hexdig[i]] = i;
	}
	if ((d = malloc(*blen)) == NULL) {
		ars_set_error(pkt, "Out of memory decoding 'hex' data");
		return NULL;
	}
	saved = d;
	while(*s) {
		int x0, x1;
		
		x0 = hextab[tolower(*s)];
		x1 = hextab[tolower(*(s+1))];
		if (x0 == 255 || x1 == 255) {
			ars_set_error(pkt, "Wrong byte for 'hex' data: '%c%c'",
					*s, *(s+1));
			free(saved);
			return NULL;
		}
		*d++ = (x0 << 4) | x1;
		s += 2;
	}
	return saved;
}

static char *ars_decode_string(struct ars_packet *pkt, char *s, int *blen)
{
	int l = strlen(s), i;
	int bl = 0;
	unsigned char *d, *saved;

	if (!hextab_initialized) {
		memset(hextab, -1, 255);
		for (i = 0; i < 16; i++)
			hextab[(int)hexdig[i]] = i;
	}
	if ((d = malloc(l)) == NULL) {
		ars_set_error(pkt, "Out of memory decoding 'str' data");
		return NULL;
	}
	saved = d;
	while(*s) {
		if (*s == '\\' && *(s+1) && *(s+2)) {
			*d++ = (hextab[(int)*(s+1)] << 4) + hextab[(int)*(s+2)];
			s += 3;
		} else {
			*d++ = *s++;
		}
		bl++;
	}
	*blen = bl;
	return saved;
}

#define ARS_DATA_BUF_SIZE 4096
int ars_d_set_data(struct ars_packet *pkt, int layer, char *f, char *v)
{
	ARS_DEF_LAYER;
	if (strcasecmp(f, "file") == 0) {
		int fd, n_read;
		unsigned char buffer[ARS_DATA_BUF_SIZE];

		if ((fd = open(v, O_RDONLY)) == -1) {
			ars_set_error(pkt, "Can't open the DATA file '%s': %s",
					v, strerror(errno));
			return -ARS_ERROR;
		}
		if ((n_read = read(fd, buffer, ARS_DATA_BUF_SIZE)) == -1) {
			close(fd);
			ars_set_error(pkt, "Can't read DATA from file: %s", strerror(errno));
			return -ARS_ERROR;
		}
		close(fd);
		if (n_read == 0)
			return -ARS_OK;
		return ars_push_data(pkt, layer, buffer, n_read);
	} else if (strcasecmp(f, "str") == 0) {
		char *binary;
		int err, blen;

		binary = ars_decode_string(pkt, v, &blen);
		if (binary == NULL)
			return -ARS_ERROR;
		err = ars_push_data(pkt, layer, binary, blen);
		free(binary);
		return err;
	} else if (strcasecmp(f, "hex") == 0) {
		char *binary;
		int err, blen;

		binary = ars_decode_hex(pkt, v, &blen);
		if (binary == NULL)
			return -ARS_ERROR;
		err = ars_push_data(pkt, layer, binary, blen);
		free(binary);
	} else if (strcasecmp(f, "uint32") == 0) {
		int err;
		__u32 t, nt;
		t = ars_atou(v);
		nt = htonl(t);
		err = ars_push_data(pkt, layer, (char*)&nt, 4);
		return err;
	} else if (strcasecmp(f, "uint24") == 0) {
		int err;
		__u32 t, nt;
		unsigned char *x = (unsigned char*) &nt;
		t = ars_atou(v);
		nt = htonl(t);
		err = ars_push_data(pkt, layer, x+1, 3);
		return err;
	} else if (strcasecmp(f, "uint16") == 0) {
		int err;
		__u16 t, nt;
		t = ars_atou(v);
		nt = htons(t);
		err = ars_push_data(pkt, layer, (char*)&nt, 2);
		return err;
	} else if (strcasecmp(f, "uint8") == 0) {
		int err;
		__u8 t;
		t = ars_atou(v);
		err = ars_push_data(pkt, layer, (char*)&t, 1);
		return err;
	} else {
		ars_set_error(pkt, "Invalid field for DATA layer: '%s'", f);
		return -ARS_INVALID;
	}
	return -ARS_OK;
}

/* A Finite state machine to build the packet using the description */
int ars_d_build(struct ars_packet *pkt, char *t)
{
	struct ars_d_keyword_info *k = NULL;
	char next[ARS_MAX_TSIZE];
	char field[ARS_MAX_TSIZE];
	int state = ARS_G_LAYER;
	int error;
	void *p;

	while ((t = ars_d_parser(t, next, ARS_MAX_TSIZE)) != NULL) {
		switch(state) {
		case ARS_G_LAYER:
			k = ars_get_keyword_by_name(next);
			if (k == NULL) {
				ars_set_error(pkt, "Unknown keyword: '%s'", next);
				return -ARS_INVALID;
			}
			__D(printf("Adding a new layer (%s)\n", next);)
			p = k->ki_add(pkt, k->ki_opt);
			if (p == NULL)
				return -ARS_INVALID;
			state = ARS_G_OBRACE_OR_PLUS;
			break;
		case ARS_G_FIELD_OR_CBRACE:
			if (next[0] == ')' && next[1] == '\0') {
				state = ARS_G_LEN_OR_PLUS;
			} else {
				strncpy(field, next, ARS_MAX_TSIZE);
				state = ARS_G_EQUAL;
			}
			break;
		case ARS_G_VALUE:
			if (k->ki_set == NULL) {
				ars_set_error(pkt, "Field specified for"
					"a layer that doesn't support fields");
				return -ARS_INVALID;
			}
			error = k->ki_set(pkt, ARS_LAST_LAYER, field, next);
			if (error != -ARS_OK)
				return error;
			state = ARS_G_COMMA_OR_CBRACE;
			break;
		case ARS_G_OBRACE_OR_PLUS:
			if (next[0] == '(' && next[1] == '\0') {
				state = ARS_G_FIELD_OR_CBRACE;
				break;
			} else if (next[0] == '+' && next[1] == '\0') {
				state = ARS_G_LAYER;
				break;
			} else {
				ars_set_error(pkt, "Missing brace or plus");
				return -ARS_INVALID;
			}
			break;
		case ARS_G_CBRACE:
			if (next[0] != ')' || next[1] != '\0') {
				ars_set_error(pkt, "Missing closed brace");
				return -ARS_INVALID;
			}
			state = ARS_G_LEN_OR_PLUS;
			break;
		case ARS_G_COMMA_OR_CBRACE:
			if (next[0] == ')' && next[1] == '\0') {
				state = ARS_G_LEN_OR_PLUS;
				break;
			} else if (next[0] == ',' && next[1] == '\0') {
				state = ARS_G_FIELD_OR_CBRACE;
				break;
			} else {
				ars_set_error(pkt, "Missing brace or comma");
				return -ARS_INVALID;
			}
			break;
		case ARS_G_LEN_OR_PLUS:
			if (next[0] == '+' && next[1] == '\0') {
				state = ARS_G_LAYER;
				break;
			}
			error = ars_d_setlayer_size(pkt, ARS_LAST_LAYER, next);
			if (error != -ARS_OK)
				return error;
			state = ARS_G_PLUS;
			break;
		case ARS_G_PLUS:
			if (next[0] != '+' || next[1] != '\0') {
				ars_set_error(pkt, "Missing plus");
				return -ARS_INVALID;
			}
			state = ARS_G_LAYER;
			break;
		case ARS_G_EQUAL:
			if (next[0] != '=' || next[1] != '\0') {
				ars_set_error(pkt, "Missing equal");
				return -ARS_INVALID;
			}
			state = ARS_G_VALUE;
			break;
		}
	}
	if (state != ARS_G_LEN_OR_PLUS && state != ARS_G_PLUS &&
	    state != ARS_G_OBRACE_OR_PLUS) {
		ars_set_error(pkt, "Packet description truncated");
		return -ARS_INVALID;
	}
	return -ARS_OK;
}
