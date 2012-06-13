/* Copyright (C) 2000,2001 Salvatore Sanfilippo <antirez@invece.org>
 * See the LICENSE file for more information.
 * 
 * TODO:
 * o Functions to add addresses and timestamps for some IP and TCP option
 * o IGMP support
 * o DNS support
 * o ARS add_build_layer() facility and Co., read the PROPOSAL file.
 */

/* $Id: ars.c,v 1.3 2004/04/14 12:30:18 antirez Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdarg.h>

#include "ars.h"

/* prototypes */
int ars_compiler_ip(struct ars_packet *pkt, int layer);
int ars_compiler_ipopt(struct ars_packet *pkt, int layer);
int ars_compiler_tcp(struct ars_packet *pkt, int layer);
int ars_compiler_tcpopt(struct ars_packet *pkt, int layer);
int ars_compiler_udp(struct ars_packet *pkt, int layer);
int ars_compiler_icmp(struct ars_packet *pkt, int layer);
int ars_compiler_igrp(struct ars_packet *pkt, int layer);
int ars_compiler_abort(struct ars_packet *pkt, int layer) { return 0; }

/* Initialize a packets context:
 * must be called before to work with the packet's layers */
int ars_init(struct ars_packet *pkt)
{
	int j;

	pkt->p_error = NULL;
	pkt->p_layer_nr = 0;
	pkt->p_options = 0;
	for (j = 0; j < ARS_MAX_LAYER; j++) {
		pkt->p_layer[j].l_size = 0;
		pkt->p_layer[j].l_flags = 0;
		pkt->p_layer[j].l_type = ARS_TYPE_NULL;
		pkt->p_layer[j].l_data = NULL;
		pkt->p_layer[j].l_packet = pkt;
	}
	for (j = 0; j < ARS_TYPE_SIZE; j++)
		pkt->p_default[j] = NULL;
	return -ARS_OK;
}

/* Destroy (free the allocated memory) a packet context */
int ars_destroy(struct ars_packet *pkt)
{
	int j;

	free(pkt->p_error);
	for (j = 0; j < ARS_MAX_LAYER; j++) {
		if (pkt->p_layer[j].l_type != ARS_TYPE_NULL &&
		    pkt->p_layer[j].l_data != NULL)
			free(pkt->p_layer[j].l_data);
	}
	return ars_init(pkt); /* Re-initialize it */
}

/* THe out of memory message must be statically allocated */
char *ars_error_nomem = "Out of memory";

/* Set the error description */
int ars_set_error(struct ars_packet *pkt, const char *fmt, ...)
{
	va_list ap;
	char buf[ARS_ERR_BUFSZ];

	if (pkt == NULL)
		return -ARS_OK;

	va_start(ap, fmt);
	vsnprintf(buf, ARS_ERR_BUFSZ, fmt, ap);
	buf[ARS_ERR_BUFSZ-1] = '\0';
	va_end(ap);
	free(pkt->p_error); /* p_error is initialized to NULL */
	if ((pkt->p_error = strdup(buf)) == NULL) {
		/* To put the error description for the -KO_NOMEM
		 * error we needs a statically allocated error message:
		 * Note that all other functions don't need to report
		 * a statically allocated error message for -KO_NOMEM
		 * it will be auto-selected if strdup() returns NULL */
		pkt->p_error = ars_error_nomem;
	}
	return -ARS_OK; /* report anyway success */
}

/* Set the default for a layer */
int ars_set_default(struct ars_packet *pkt, int layer_type, void *def)
{
	pkt->p_default[layer_type] = def;
	return -ARS_OK;
}

/* return nonzero if the packet is full */
int ars_nospace(struct ars_packet *pkt)
{
	return (pkt->p_layer_nr == ARS_MAX_LAYER);
}

/* Check if the layer number is valid */
int ars_valid_layer(int layer)
{
	if (layer < 0 || layer >= ARS_MAX_LAYER)
		return -ARS_INVALID;
	return -ARS_OK;
}

/* Add an a generic layer */
int ars_add_generic(struct ars_packet *pkt, size_t size, int type)
{
	int layer;

	if (ars_nospace(pkt)) {
		ars_set_error(pkt, "No space for the next layer");
		return -ARS_NOSPACE;
	}
	layer = pkt->p_layer_nr;
	/* You may want to create a 0 len layer and then realloc */
	if (size != 0) {
		pkt->p_layer[layer].l_data = malloc(size);
		if (pkt->p_layer[layer].l_data == NULL) {
			ars_set_error(pkt, "Out of memory adding a new layer");
			return -ARS_NOMEM;
		}
		memset(pkt->p_layer[layer].l_data, 0, size);
		/* Copy the default if any */
		if (pkt->p_default[type] != NULL) {
			memcpy(pkt->p_layer[layer].l_data,
			       pkt->p_default[type], size);
		}
	}
	pkt->p_layer[layer].l_type = type;
	pkt->p_layer[layer].l_size = size;
	return -ARS_OK;
}

/* Add an IP layer */
void *ars_add_iphdr(struct ars_packet *pkt, int unused)
{
	int retval;

	retval = ars_add_generic(pkt, sizeof(struct ars_iphdr), ARS_TYPE_IP);
	if (retval != -ARS_OK)
		return NULL;
	pkt->p_layer_nr++;
	return pkt->p_layer[pkt->p_layer_nr-1].l_data;
}

/* Add on IP option */
void *ars_add_ipopt(struct ars_packet *pkt, int option)
{
	int retval;
	struct ars_ipopt *ipopt;
	int opt_len;

	switch(option) {
	case ARS_IPOPT_END:
	case ARS_IPOPT_NOOP:
		opt_len = 1;
		break;
	case ARS_IPOPT_SEC:
		opt_len = 11;
		break;
	case ARS_IPOPT_SID:
		opt_len = 4;
		break;
	case ARS_IPOPT_LSRR:
	case ARS_IPOPT_SSRR:
	case ARS_IPOPT_RR:
	case ARS_IPOPT_TIMESTAMP:
		/* We allocate the max (40 bytes) but the real layer size
		 * may be modified by ars_ipopt_set*() functions */
		opt_len = 40;
		break;
	default:
		return NULL; /* Unsupported option */
		break;
	}

	retval = ars_add_generic(pkt, opt_len, ARS_TYPE_IPOPT);
	if (retval != -ARS_OK)
		return NULL;
	ipopt = pkt->p_layer[pkt->p_layer_nr].l_data;
	pkt->p_layer_nr++;

	ipopt->kind = option;
	/* END and NOOP hasn't the length byte */
	if (option == ARS_IPOPT_END || option == ARS_IPOPT_NOOP)
		return ipopt;
	ipopt->len = opt_len; /* the default, can be modified inside switch() */
	/* Perform some special operation for some option */
	switch(option) {
	case ARS_IPOPT_LSRR: /* ars_ipopt_setls() will change some field */
	case ARS_IPOPT_SSRR: /* ars_ipopt_setss() will change some field */
	case ARS_IPOPT_RR:   /* ars_ipopt_setrr() will change some field */
		/* RFC 791 needs the roomlen - 3 octects, so the gateways
		 * can compare len and ptr to check for room.
		 * Try to break this to stress lame TCP/IP implementation */
		ipopt->len = opt_len - 2 - 3;
		ipopt->un.rr.ptr = 4;
		break;
	case ARS_IPOPT_TIMESTAMP:
		ipopt->len = opt_len - 2 - 4;
		ipopt->un.ts.ptr = 5;
		ipopt->un.ts.flags = ARS_IPOPT_TS_TSONLY; /* default */
		break;
	}
	return ipopt;
}

/* Add a UDP layer */
void *ars_add_udphdr(struct ars_packet *pkt, int unused)
{
	int retval;

	retval = ars_add_generic(pkt, sizeof(struct ars_udphdr), ARS_TYPE_UDP);
	if (retval != -ARS_OK)
		return NULL;
	pkt->p_layer_nr++;
	return pkt->p_layer[pkt->p_layer_nr-1].l_data;
}

/* Add a TCP layer */
void *ars_add_tcphdr(struct ars_packet *pkt, int unused)
{
	int retval;

	retval = ars_add_generic(pkt, sizeof(struct ars_tcphdr), ARS_TYPE_TCP);
	if (retval != -ARS_OK)
		return NULL;
	pkt->p_layer_nr++;
	return pkt->p_layer[pkt->p_layer_nr-1].l_data;
}

/* Add TCP options */
void *ars_add_tcpopt(struct ars_packet *pkt, int option)
{
	int retval;
	struct ars_tcpopt *tcpopt;
	int opt_len;

	switch(option) {
	case ARS_TCPOPT_NOP:
	case ARS_TCPOPT_EOL:
		opt_len = 1;
		break;
	case ARS_TCPOPT_MAXSEG:
		opt_len = 4;
		break;
	case ARS_TCPOPT_WINDOW:
		opt_len = 3;
		break;
	case ARS_TCPOPT_SACK_PERM:
		opt_len = 2;
		break;
	case ARS_TCPOPT_SACK:
		opt_len = 8*4+2;
		break;
	case ARS_TCPOPT_ECHOREQUEST:
	case ARS_TCPOPT_ECHOREPLY:
		opt_len = 6;
		break;
	case ARS_TCPOPT_TIMESTAMP:
		opt_len = 10;
		break;
	default:
		return NULL; /* Unsupported option */
		break;
	}

	retval = ars_add_generic(pkt, opt_len, ARS_TYPE_TCPOPT);
	if (retval != -ARS_OK)
		return NULL;
	tcpopt = pkt->p_layer[pkt->p_layer_nr].l_data;
	pkt->p_layer_nr++;

	tcpopt->kind = option;
	/* EOL and NOP lacks the len field */
	if (option != ARS_TCPOPT_EOL && option != ARS_TCPOPT_NOP)
		tcpopt->len = opt_len;

	/* Perform some special operation for the option */
	switch(option) {
	case ARS_TCPOPT_ECHOREQUEST:
	case ARS_TCPOPT_ECHOREPLY:
		memset(tcpopt->un.echo.info, 0, 4);
		break;
	case ARS_TCPOPT_TIMESTAMP:
		memset(tcpopt->un.timestamp.tsval, 0, 4);
		memset(tcpopt->un.timestamp.tsecr, 0, 4);
		break;
	}
	return tcpopt;
}

/* Add an ICMP layer */
void *ars_add_icmphdr(struct ars_packet *pkt, int unused)
{
	int retval;
	struct ars_icmphdr *icmp;

	retval = ars_add_generic(pkt, sizeof(struct ars_icmphdr),ARS_TYPE_ICMP);
	if (retval != -ARS_OK)
		return NULL;
	icmp = pkt->p_layer[pkt->p_layer_nr].l_data;
	icmp->type = ARS_ICMP_ECHO;
	icmp->code = 0;
	pkt->p_layer_nr++;
	return (struct ars_icmphdr*) pkt->p_layer[pkt->p_layer_nr-1].l_data;
}

/* Add an IGRP layer */
void *ars_add_igrphdr(struct ars_packet *pkt, int unused)
{
	int retval;
	struct ars_igrphdr *igrp;

	retval = ars_add_generic(pkt, sizeof(struct ars_igrphdr),ARS_TYPE_IGRP);
	if (retval != -ARS_OK)
		return NULL;
	igrp = pkt->p_layer[pkt->p_layer_nr].l_data;
	igrp->opcode = ARS_IGRP_OPCODE_REQUEST;
	igrp->version = 1;
	igrp->edition = 0;
	igrp->autosys = 0;
	igrp->interior = 0;
	igrp->system = 0;
	igrp->exterior = 0;
	pkt->p_layer_nr++;
	return pkt->p_layer[pkt->p_layer_nr-1].l_data;
}

/* Add an IGRP entry */
void *ars_add_igrpentry(struct ars_packet *pkt, int unused)
{
	int retval;

	retval = ars_add_generic(pkt, sizeof(struct ars_igrpentry),ARS_TYPE_IGRPENTRY);
	if (retval != -ARS_OK)
		return NULL;
	pkt->p_layer_nr++;
	return pkt->p_layer[pkt->p_layer_nr-1].l_data;
}

/* Add data, for IP-RAW, TCP, UDP, and so on */
void *ars_add_data(struct ars_packet *pkt, int size)
{
	int retval;
	static void *ptr = "zzappt"; /* we can't return NULL for size == 0 */

	if (size < 0) {
		ars_set_error(pkt, "Tryed to add a DATA layer with size < 0");
		return NULL;
	}
	retval = ars_add_generic(pkt, size, ARS_TYPE_DATA);
	if (retval != -ARS_OK)
		return NULL;
	pkt->p_layer_nr++;
	if (size > 0)
		return pkt->p_layer[pkt->p_layer_nr-1].l_data;
	else
		return ptr;
}

/* Remove a layer */
int ars_remove_layer(struct ars_packet *pkt, int layer)
{
	if (layer == ARS_LAST_LAYER)
		layer = pkt->p_layer_nr -1;
	if (ars_valid_layer(layer) != -ARS_OK)
		return -ARS_INVALID;

	free(pkt->p_layer[layer].l_data); /* No problem if it's NULL */
	pkt->p_layer[layer].l_type = ARS_TYPE_NULL;
	pkt->p_layer[layer].l_size = 0;
	pkt->p_layer[layer].l_flags = 0;
	pkt->p_layer[layer].l_data = NULL;
	pkt->p_layer[layer].l_packet = pkt;
	return -ARS_OK;
}

/* Return the sum of the size of the specifed layer and of all the
 * following layers */
size_t ars_relative_size(struct ars_packet *pkt, int layer_nr)
{
	int j = layer_nr, rel_size = 0;

	while (j < ARS_MAX_LAYER && pkt->p_layer[j].l_type != ARS_TYPE_NULL) {
		rel_size += pkt->p_layer[j].l_size;
		j++;
	}
	return rel_size;
}

/* Just a short cut for ars_relative_size(), to get the total size */
size_t ars_packet_size(struct ars_packet *pkt)
{
	return ars_relative_size(pkt, 0);
}

/* from R. Stevens's Network Programming */
u_int16_t ars_cksum(void *vbuf, size_t nbytes)
{
	u_int16_t *buf = (u_int16_t*) vbuf;
	u_int32_t sum;
	u_int16_t oddbyte;

	sum = 0;
	while (nbytes > 1) {
		sum += *buf++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_int16_t *) &oddbyte) = *(u_int16_t *) buf;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (u_int16_t) ~sum;
}

/* Multiple buffers checksum facility */
u_int16_t ars_multi_cksum(struct mc_context *c, int op, void *vbuf,
							size_t nbytes)
{
	u_int16_t *buf = (u_int16_t*) vbuf;
	u_int32_t sum;
	u_int16_t oddbyte;
	void *tmp;

	if (op == ARS_MC_INIT) {
		c->oddbyte_flag = 0;
		c->old = 0;
		return -ARS_OK;
	} else if (op == ARS_MC_UPDATE) {
		if (c->oddbyte_flag) {
			u_int8_t *x = (u_int8_t*)&oddbyte;
			oddbyte = 0;
			*((u_int16_t *) &oddbyte) = c->oddbyte << 8;
			*((u_int16_t *) &oddbyte) |= *(u_int16_t *) buf;
			oddbyte = (x[0] << 8) | x[1]; /* fix endianess */
			c->old += oddbyte;
			nbytes--;
			c->oddbyte_flag = 0;
			/* We need to stay aligned -- bad slowdown, fix? */
			tmp = alloca(nbytes);
			memcpy(tmp, vbuf+1, nbytes);
			buf = tmp;
		}
		sum = c->old;
		while (nbytes > 1) {
			sum += *buf++;
			nbytes -= 2;
		}
		c->old = sum;
		if (nbytes == 1) {
			c->oddbyte = *(u_int16_t*) buf;
			c->oddbyte_flag++;
		}
		return -ARS_OK;
	} else if (op == ARS_MC_FINAL) {
		sum = c->old;
		if (c->oddbyte_flag == 1) {
			oddbyte = 0;
			*((u_int16_t *) &oddbyte) = c->oddbyte;
			sum += oddbyte;
		}
		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);
		return (u_int16_t) ~sum;
	} else {
		assert("else reached in ars_multi_cksum()" == "");
	}
	return 0; /* unreached, here to prevent warnings */
}

/* The ARS compiler table is just a function pointers array:
 * For example to select the right function to compile an IP
 * layer use: ars_compiler[ARS_TYPE_IP](pkt, layer);
 * You can, of course, add your protocols and compilers:
 *
 * WARNING: take it syncronized with ars.h ARS_TYPE_* defines
 */
struct ars_layer_info ars_linfo[ARS_TYPE_SIZE] = {
/* NAME			COMPILER		ID *
 * ----                 --------                -- */
{ "NULL",		ars_compiler_abort,	NULL,			0 },
{ "IP",			ars_compiler_ip,	ars_rapd_ip,		1 },
{ "IPOPT",		ars_compiler_ipopt,	ars_rapd_ipopt,		2 },
{ "ICMP",		ars_compiler_icmp,	ars_rapd_icmp,		3 },
{ "UDP",		ars_compiler_udp,	ars_rapd_udp,		4 },
{ "TCP",		ars_compiler_tcp,	ars_rapd_tcp,		5 },
{ "TCPOPT",		ars_compiler_tcpopt,	ars_rapd_tcpopt,	6 },
{ "IGRP", 		ars_compiler_igrp,	ars_rapd_igrp,		7 },
{ "IGRPENTRY",		NULL,			ars_rapd_igrpentry,	8 },
{ NULL, NULL, NULL, 9 },
{ NULL, NULL, NULL, 10 },
{ NULL, NULL, NULL, 11 },
{ NULL, NULL, NULL, 12 },
{ NULL, NULL, NULL, 13 },
{ NULL, NULL, NULL, 14 },
{ NULL, NULL, NULL, 15 },
{ NULL, NULL, NULL, 16 },
{ NULL, NULL, NULL, 17 },
{ NULL, NULL, NULL, 18 },
{ NULL, NULL, NULL, 19 },
{ NULL, NULL, NULL, 20 },
{ NULL, NULL, NULL, 21 },
{ NULL, NULL, NULL, 22 },
{ NULL, NULL, NULL, 23 },
{ NULL, NULL, NULL, 24 },
{ NULL, NULL, NULL, 25 },
{ NULL, NULL, NULL, 26 },
{ NULL, NULL, NULL, 27 },
{ NULL, NULL, NULL, 28 },
{ NULL, NULL, NULL, 29 },
{ NULL, NULL, NULL, 30 },
{ "DATA",		NULL,			ars_rapd_data,		31 }
};

/* This function call the right compiler for all the layers of the packet:
 * A compiler just set the protocol fields like the checksum, len, and so on
 * accordly to the following layers.
 * Note that the layers are compiled from the last to the first, to ensure
 * that the checksum and other dependences are sane. */
int ars_compile(struct ars_packet *pkt)
{
	int j, err;

	for (j = pkt->p_layer_nr - 1; j >= 0; j--) {
		__D(printf("Compiling layer %d\n", j);)
		/* Skip NULL compilers */
		if (ars_linfo[pkt->p_layer[j].l_type].li_compiler != NULL) {
			/* Call the compiler */
			err = ars_linfo[pkt->p_layer[j].l_type].li_compiler(pkt, j);
			if (err != -ARS_OK)
				return err;
		}
	}
	return -ARS_OK;
}

/* The IP compiler: probably the more complex, but still simple */
int ars_compiler_ip(struct ars_packet *pkt, int layer)
{
	struct ars_iphdr *ip = pkt->p_layer[layer].l_data;
	int j = layer, err;
	int flags = pkt->p_layer[layer].l_flags;
	int ipoptlen = 0;
	struct mc_context mc; /* multi-buffer checksum context */

	/* IP version */
	if (ARS_DONTTAKE(flags, ARS_TAKE_IP_VERSION))
		ip->version = 4;
	/* IP header len */
	if (ARS_DONTTAKE(flags, ARS_TAKE_IP_HDRLEN)) {
		ip->ihl = (ARS_IPHDR_SIZE >> 2);
		/* Add IP options len */
		for (j = layer+1; j < ARS_MAX_LAYER; j++) {
			if (pkt->p_layer[j].l_type != ARS_TYPE_IPOPT)
				break;
			ipoptlen += pkt->p_layer[j].l_size; 
		}
		ip->ihl += ipoptlen >> 2;
	}
	/* IP tot len */
	if (ARS_DONTTAKE(flags, ARS_TAKE_IP_TOTLEN))
		ip->tot_len = htons(ars_relative_size(pkt, layer));
	/* IP protocol field */
	if (ARS_DONTTAKE(flags, ARS_TAKE_IP_PROTOCOL)) {
		ip->protocol = ARS_IPPROTO_RAW; /* This is the default */
		while (j < ARS_MAX_LAYER) {
			if (pkt->p_layer[j].l_type == ARS_TYPE_IPOPT) {
				j++;
				continue;
			}
			switch(pkt->p_layer[j].l_type) {
			case ARS_TYPE_IP:
				ip->protocol = ARS_IPPROTO_IPIP;
				break;
			case ARS_TYPE_ICMP:
				ip->protocol = ARS_IPPROTO_ICMP;
				break;
			case ARS_TYPE_UDP:
				ip->protocol = ARS_IPPROTO_UDP;
				break;
			case ARS_TYPE_TCP:
				ip->protocol = ARS_IPPROTO_TCP;
				break;
			case ARS_TYPE_IGRP:
				ip->protocol = ARS_IPPROTO_IGRP;
				break;
			}
			break;
		}
	}
	/* We always calculate the IP checksum, since the kernel
	 * do it only for the first IP header in the datagram */
	if (ARS_DONTTAKE(flags, ARS_TAKE_IP_CKSUM)) {
		ip->check = 0;
		ars_multi_cksum(&mc, ARS_MC_INIT, NULL, 0);
		err = ars_multi_cksum(&mc, ARS_MC_UPDATE, ip, ARS_IPHDR_SIZE);
		if (err != -ARS_OK)
			return err;
		for (j = layer+1; j < ARS_MAX_LAYER; j++) {
			if (pkt->p_layer[j].l_type != ARS_TYPE_IPOPT)
				break;
			err = ars_multi_cksum(&mc, ARS_MC_UPDATE,
						pkt->p_layer[j].l_data,
						pkt->p_layer[j].l_size);
			if  (err != -ARS_OK)
				return err;
		}
		ip->check = ars_multi_cksum(&mc, ARS_MC_FINAL, NULL, 0);
	}
	return -ARS_OK;
}

/* The ip options compiler: do just option padding with NOP options */
int ars_compiler_ipopt(struct ars_packet *pkt, int layer)
{
	int j, opt_size;

	/* Padding is needed only in the last IP option */
	if (layer != ARS_MAX_LAYER-1 &&
	    pkt->p_layer[layer+1].l_type == ARS_TYPE_IPOPT)
		return ARS_OK;

	/* Search the layer of the relative first IP option */
	j = layer - 1; /* We know that 'layer' is an IP option */
	while (j < ARS_MAX_LAYER && j >= 0 &&
	       pkt->p_layer[j].l_type == ARS_TYPE_IPOPT)
		j--;
	j++;
	__D(printf("First IP OPTION layer is %d\n", j);)
	opt_size = ars_relative_size(pkt, j) - ars_relative_size(pkt, layer+1);
	__D(printf("IP OPTION size %d\n", opt_size);)
	if (opt_size % 4) {
		int padding = 4 - (opt_size % 4);
		unsigned char *t;
		int cur_size = pkt->p_layer[layer].l_size;

		__D(printf("IP OPTION at layer %d needs %d bytes "
			   "of padding\n", layer, padding);)
		t = realloc(pkt->p_layer[layer].l_data, cur_size + padding);
		if (t == NULL) {
			ars_set_error(pkt, "Out of memory padding IP options");
			return -ARS_NOMEM;
		}
		memset(t+cur_size, ARS_IPOPT_NOP, padding);
		__D(printf("The last IP OPTION length was: %d\n", cur_size);)
		pkt->p_layer[layer].l_data = t;
		pkt->p_layer[layer].l_size += padding;
		__D(printf("After padding it is: %d\n", pkt->p_layer[layer].l_size);)
	}
	return -ARS_OK;
}

/* Compute the UDP and TCP checksum using the pseudoheader.
 * Note that this functions automatically care about TCP/UDP data.
 * FIXME: this doesn't work when the IP source address is 0.0.0.0 */
int ars_udptcp_cksum(struct ars_packet *pkt, int layer, u_int16_t *sum)
{
	struct ars_iphdr *ip;
	struct ars_pseudohdr pseudo;
	struct mc_context mc; /* multi-buffer checksum context */
	int j = layer - 1, err;

	/* search the first IP layer on the left:
	 * it returns an error if between the IP and
	 * the TCP layer there aren't just IPOPT layers:
	 * even with malformed packets this does not
	 * makes sense. */
	while (j > 0 && pkt->p_layer[j].l_type == ARS_TYPE_IPOPT)
		j--;
	if (pkt->p_layer[j].l_type != ARS_TYPE_IP) {
		ars_set_error(pkt, "TCP/UDP checksum requested, but IP header "
				    "not found");
		return -ARS_INVALID;
	}
	ip = pkt->p_layer[j].l_data;
	memset(&pseudo, 0, sizeof(pseudo)); /* actually not needed */
	/* Copy the src and dst IP address */
	memcpy(&pseudo.saddr, &ip->saddr, 4);
	memcpy(&pseudo.daddr, &ip->daddr, 4);
	pseudo.protocol = (pkt->p_layer[layer].l_type == ARS_TYPE_TCP)
		? ARS_IPPROTO_TCP : ARS_IPPROTO_UDP;
	pseudo.lenght = htons(ars_relative_size(pkt, layer));

	/* Finally do the checksum */
	ars_multi_cksum(&mc, ARS_MC_INIT, NULL, 0);
	err = ars_multi_cksum(&mc, ARS_MC_UPDATE, &pseudo, sizeof(pseudo));
	if (err != -ARS_OK)
		return err;
	for (j = layer; j < ARS_MAX_LAYER; j++) {
		if (pkt->p_layer[j].l_type == ARS_TYPE_NULL)
			break;
		err = ars_multi_cksum(&mc, ARS_MC_UPDATE,
					pkt->p_layer[j].l_data,
					pkt->p_layer[j].l_size);
		if  (err != -ARS_OK)
			return err;
	}
	*sum = ars_multi_cksum(&mc, ARS_MC_FINAL, NULL, 0);
	return -ARS_OK;
}

/* The tcp compiler */
int ars_compiler_tcp(struct ars_packet *pkt, int layer)
{
	struct ars_tcphdr *tcp = pkt->p_layer[layer].l_data;
	int j, err, tcpoptlen = 0;
	int flags = pkt->p_layer[layer].l_flags;

	if (ARS_DONTTAKE(flags, ARS_TAKE_TCP_HDRLEN)) {
		tcp->th_off = ARS_TCPHDR_SIZE >> 2;
		/* Add the len of the options */
		for (j = layer+1; j < ARS_MAX_LAYER; j++) {
			if (pkt->p_layer[j].l_type != ARS_TYPE_TCPOPT)
				break;
			tcpoptlen += pkt->p_layer[j].l_size;
		}
		tcp->th_off += tcpoptlen >> 2;
	}
	if (ARS_DONTTAKE(flags, ARS_TAKE_TCP_CKSUM)) {
		tcp->th_sum = 0;
		err = ars_udptcp_cksum(pkt, layer, &tcp->th_sum);
		if (err != -ARS_OK)
			return err;
	}
	return -ARS_OK;
}

/* The tcp options compiler: do just option padding with NOP options */
int ars_compiler_tcpopt(struct ars_packet *pkt, int layer)
{
	int j, opt_size;

	/* Padding is needed only in the last TCP option */
	if (layer != ARS_MAX_LAYER-1 &&
	    pkt->p_layer[layer+1].l_type == ARS_TYPE_TCPOPT)
		return ARS_OK;

	/* Search the layer of the relative first TCP option */
	j = layer - 1; /* We know that 'layer' is a tcp option */
	while (j < ARS_MAX_LAYER && j >= 0 &&
	       pkt->p_layer[j].l_type == ARS_TYPE_TCPOPT)
		j--;
	j++;
	__D(printf("First TCP OPTION layer is %d\n", j);)
	opt_size = ars_relative_size(pkt, j) - ars_relative_size(pkt, layer+1);
	__D(printf("TCP OPTION size %d\n", opt_size);)
	if (opt_size % 4) {
		int padding = 4 - (opt_size % 4);
		unsigned char *t;
		int cur_size = pkt->p_layer[layer].l_size;

		__D(printf("TCP OPTION at layer %d needs %d bytes "
			   "of padding\n", layer, padding);)
		t = realloc(pkt->p_layer[layer].l_data, cur_size + padding);
		if (t == NULL) {
			ars_set_error(pkt, "Out of memory padding TCP options");
			return -ARS_NOMEM;
		}
		memset(t+cur_size, ARS_TCPOPT_NOP, padding);
		pkt->p_layer[layer].l_size += padding;
	}
	return -ARS_OK;
}

/* The udp compiler, very simple */
int ars_compiler_udp(struct ars_packet *pkt, int layer)
{
	struct ars_udphdr *udp = pkt->p_layer[layer].l_data;
	int err;
	int flags = pkt->p_layer[layer].l_flags;

	if (ARS_DONTTAKE(flags, ARS_TAKE_UDP_LEN))
		udp->uh_ulen = htons(ars_relative_size(pkt, layer));

	if (ARS_DONTTAKE(flags, ARS_TAKE_UDP_CKSUM)) {
		udp->uh_sum = 0;
		err = ars_udptcp_cksum(pkt, layer, &udp->uh_sum);
		if (err != -ARS_OK)
			return err;
	}
	return -ARS_OK;
}

/* The icmp compiler, just compute the checksum */
int ars_compiler_icmp(struct ars_packet *pkt, int layer)
{
	struct ars_icmphdr *icmp = pkt->p_layer[layer].l_data;
	struct mc_context mc; /* multi-buffer checksum context */
	int err, j;
	int flags = pkt->p_layer[layer].l_flags;

	if (ARS_DONTTAKE(flags, ARS_TAKE_ICMP_CKSUM)) {
		icmp->checksum = 0;
		ars_multi_cksum(&mc, ARS_MC_INIT, NULL, 0);
		for (j = layer; j < ARS_MAX_LAYER; j++) {
			if (pkt->p_layer[j].l_type == ARS_TYPE_NULL)
				break;
			err = ars_multi_cksum(&mc, ARS_MC_UPDATE,
						pkt->p_layer[j].l_data,
						pkt->p_layer[j].l_size);
			if  (err != -ARS_OK)
				return err;
		}
		icmp->checksum = ars_multi_cksum(&mc, ARS_MC_FINAL, NULL, 0);
	}
	return -ARS_OK;
}

/* The igrp compiler, just compute the checksum */
int ars_compiler_igrp(struct ars_packet *pkt, int layer)
{
	struct ars_igrphdr *igrp = pkt->p_layer[layer].l_data;
	struct mc_context mc; /* multi-buffer checksum context */
	int err, j;
	int flags = pkt->p_layer[layer].l_flags;

	if (ARS_DONTTAKE(flags, ARS_TAKE_IGRP_CKSUM)) {
		igrp->checksum = 0;
		ars_multi_cksum(&mc, ARS_MC_INIT, NULL, 0);
		for (j = layer; j < ARS_MAX_LAYER; j++) {
			if (pkt->p_layer[j].l_type == ARS_TYPE_NULL)
				break;
			err = ars_multi_cksum(&mc, ARS_MC_UPDATE,
						pkt->p_layer[j].l_data,
						pkt->p_layer[j].l_size);
			if  (err != -ARS_OK)
				return err;
		}
		igrp->checksum = ars_multi_cksum(&mc, ARS_MC_FINAL, NULL, 0);
	}
	return -ARS_OK;
}

/* Open a raw socket, ready for IP header creation and broadcast addresses */
int ars_open_rawsocket(struct ars_packet *pkt)
{
	int s;
	const int one = 1;

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		ars_set_error(pkt, "Can't open the raw socket");
		return -ARS_ERROR;
	}
	if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char*)&one,
		sizeof(one)) == -1 ||
	    setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&one,
		sizeof(one)) == -1)
	{
		close(s);
		ars_set_error(pkt, "Can't set socket options");
		return -ARS_ERROR;
	}
	return s;
}

/* Create the packets using the layers. This function is often called
 * after the layers compilation. Note that since the packet created
 * is sane the strange-rawsocket-behaviour of some *BSD will not
 * be able to send this packet. Use the function ars_bsd_fix() to fix it.
 * WARNING: The packets returned is malloc()ated, free it */
int ars_build_packet(struct ars_packet *pkt, unsigned char **packet, size_t *size)
{
	size_t tot_size, offset = 0;
	int j = 0;

	if ((tot_size = ars_packet_size(pkt)) == 0) {
		ars_set_error(pkt, "Total size 0 building the packet");
		return -ARS_INVALID;
	}
	if ((*packet = malloc(tot_size)) == NULL) {
		ars_set_error(pkt, "Out of memory building the packet");
		return -ARS_NOMEM;
	}
	while (j < ARS_MAX_LAYER && pkt->p_layer[j].l_type != ARS_TYPE_NULL) {
		memcpy((*packet)+offset, pkt->p_layer[j].l_data,
					 pkt->p_layer[j].l_size);
		offset += pkt->p_layer[j].l_size;
		j++;
	}
	*size = tot_size;
	return -ARS_OK;
}

/* FreeBSD and NetBSD have a strange raw socket layer :(
 * Call this function anyway to increase portability
 * since it does not perform any operation if the
 * system isn't FreeBSD or NetBSD. */
int ars_bsd_fix(struct ars_packet *pkt, unsigned char *packet, size_t size)
{
	struct ars_iphdr *ip;

	if (pkt->p_layer[0].l_type != ARS_TYPE_IP ||
	    size < sizeof(struct ars_iphdr)) {
		ars_set_error(pkt, "BSD fix requested, but layer 0 not IP");
		return -ARS_INVALID;
	}
	ip = (struct ars_iphdr*) packet;
#if defined OSTYPE_FREEBSD || defined OSTYPE_NETBSD || defined OSTYPE_BSDI
	ip->tot_len = ntohs(ip->tot_len);
	ip->frag_off = ntohs(ip->frag_off);
#endif
	return -ARS_OK;
}

/* Set the flags for some layer: if layer == -1 the last layer will be used */
int ars_set_flags(struct ars_packet *pkt, int layer, int flags)
{
	if (layer == ARS_LAST_LAYER)
		layer = pkt->p_layer_nr - 1;
	if (layer < 0 || layer >= ARS_MAX_LAYER) {
		ars_set_error(pkt, "Invalid layer setting layer flags");
		return -ARS_INVALID;
	}
	pkt->p_layer[layer].l_flags = flags;
	return -ARS_OK;
}

/* Build, fix, and send the packet */
int ars_send(int s, struct ars_packet *pkt, struct sockaddr *sa, socklen_t slen)
{
	struct sockaddr_in sain;
	struct sockaddr *_sa = sa;
	unsigned char *packet;
	size_t size;
	int error;

	/* Perform the socket address completion if sa == NULL */
	if (sa == NULL) {
		struct ars_iphdr *ip;

		memset(&sain, 0, sizeof(sain));
		sain.sin_family = AF_INET;
		/* The first layer MUST be IP if the user requested
		 * the socket address completion */
		if (pkt->p_layer[0].l_type != ARS_TYPE_IP) {
			ars_set_error(pkt, "socket address completion"
				"requested, but layer 0 isn't IP");
			return -ARS_ERROR;
		}
		ip = (struct ars_iphdr*) pkt->p_layer[0].l_data;
		memcpy(&sain.sin_addr.s_addr, &ip->daddr, 4);
		_sa = (struct sockaddr*) &sain;
		slen = sizeof(sain);
	}
	if ((error = ars_build_packet(pkt, &packet, &size)) != ARS_OK)
		return error;
	if ((error = ars_bsd_fix(pkt, packet, size)) != ARS_OK)
		return error;
	error = sendto(s, packet, size, 0, _sa, slen);
	free(packet);
	return (error != -1) ? -ARS_OK : -ARS_ERROR;
}

/* Resolve an hostname and write to 'dest' the IP */
int ars_resolve(struct ars_packet *pkt, u_int32_t *dest, char *hostname)
{
	struct sockaddr_in sa;

	if (inet_aton(hostname, &sa.sin_addr) == 0) {
		struct hostent *he;
		he = gethostbyname(hostname);
		if (he == NULL) {
			ars_set_error(pkt, "Can't resolve the hostname");
			return -ARS_ERROR;
		}
		sa.sin_addr.s_addr = ((struct in_addr*) he->h_addr)->s_addr;
	}
	memcpy(dest, &sa.sin_addr.s_addr, sizeof(u_int32_t));
	return -ARS_OK;
}
