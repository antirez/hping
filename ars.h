/* Copyright (C) 2000,2001 Salvatore Sanfilippo <antirez@invece.org>
 * See the LICENSE file for more information. */

/* $Id: ars.h,v 1.4 2004/06/04 07:22:38 antirez Exp $ */

#ifndef _ARS_H
#define _ARS_H

/* define before including sys/socket.h */
#if defined(__APPLE__) && !defined(_BSD_SOCKLEN_T_)
#define _BSD_SOCKLEN_T_ int
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include "systype.h"
#include "in.h"
#include "byteorder.h"
#include "adbuf.h"
#include "fixtypes.h"

#ifndef TRUE
#define TRUE	1
#define FALSE	0
#endif


#ifndef MIN
#define MIN(x,y)	((x)<(y)?(x):(y))
#endif

#ifndef MAX
#define MAX(x,y)	((x)>(y)?(x):(y))
#endif

#ifdef DEBUG
#define __D(x) x
#else
#define __D(x) do { } while (0);
#endif

#ifndef __u8
#define __u8	u_int8_t
#define __u16	u_int16_t
#define __u32	u_int32_t
#endif

/* error codes */
#define ARS_OK          0
#define ARS_ERROR	1
#define ARS_NOSPACE     2
#define ARS_NOMEM       3
#define ARS_INVALID	4

/* Headers size */
#define ARS_ICMPHDR_SIZE	sizeof(struct ars_icmphdr)
#define ARS_UDPHDR_SIZE		sizeof(struct ars_udphdr)
#define ARS_TCPHDR_SIZE		sizeof(struct ars_tcphdr)
#define ARS_IPHDR_SIZE		sizeof(struct ars_iphdr)
#define ARS_PSEUDOHDR_SIZE	sizeof(struct pseudohdr)
#define ARS_IGRPHDR_SIZE	sizeof(struct ars_igrphdr)
#define ARS_IGRPENTRY_SIZE	sizeof(struct ars_igrpentry)

/* IP defines */
#define ARS_MAX_IP_SIZE		65535

#define ARS_IP_MF ((unsigned short)0x2000)	/* more fragments */
#define ARS_IP_DF ((unsigned short)0x4000)	/* dont fragment */
#define ARS_IP_RF ((unsigned short)0x8000)	/* reserved fragment flag */

#define ARS_IPOPT_COPY		0x80
#define ARS_IPOPT_CLASS_MASK	0x60
#define ARS_IPOPT_NUMBER_MASK	0x1f

#define	ARS_IPOPT_COPIED(o)		((o)&ARS_IPOPT_COPY)
#define	ARS_IPOPT_CLASS(o)		((o)&ARS_IPOPT_CLASS_MASK)
#define	ARS_IPOPT_NUMBER(o)		((o)&ARS_IPOPT_NUMBER_MASK)

#define	ARS_IPOPT_CONTROL		0x00
#define	ARS_IPOPT_RESERVED1		0x20
#define	ARS_IPOPT_MEASUREMENT		0x40
#define	ARS_IPOPT_RESERVED2		0x60

#define ARS_IPOPT_END		(0 |ARS_IPOPT_CONTROL)
#define ARS_IPOPT_NOOP		(1 |ARS_IPOPT_CONTROL)
#define ARS_IPOPT_SEC		(2 |ARS_IPOPT_CONTROL|ARS_IPOPT_COPY)
#define ARS_IPOPT_LSRR		(3 |ARS_IPOPT_CONTROL|ARS_IPOPT_COPY)
#define ARS_IPOPT_TIMESTAMP	(4 |ARS_IPOPT_MEASUREMENT)
#define ARS_IPOPT_RR		(7 |ARS_IPOPT_CONTROL)
#define ARS_IPOPT_SID		(8 |ARS_IPOPT_CONTROL|ARS_IPOPT_COPY)
#define ARS_IPOPT_SSRR		(9 |ARS_IPOPT_CONTROL|ARS_IPOPT_COPY)
#define ARS_IPOPT_RA		(20|ARS_IPOPT_CONTROL|ARS_IPOPT_COPY)

#define ARS_IPOPT_OPTVAL 0
#define ARS_IPOPT_OLEN   1
#define ARS_IPOPT_OFFSET 2
#define ARS_IPOPT_MINOFF 4
#define ARS_MAX_IPOPTLEN 40
#define ARS_IPOPT_NOP ARS_IPOPT_NOOP
#define ARS_IPOPT_EOL ARS_IPOPT_END
#define ARS_IPOPT_TS  ARS_IPOPT_TIMESTAMP

#define	ARS_IPOPT_TS_TSONLY	0		/* timestamps only */
#define	ARS_IPOPT_TS_TSANDADDR	1		/* timestamps and addresses */
#define	ARS_IPOPT_TS_PRESPEC	3		/* specified modules only */

/* IPV4 and IPV6 string rappresentation len */
#define ARS_INET_ADDRSTRLEN	16
#define ARS_INET6_ADDRSTRLEN	46

/* TCP */
#define ARS_TCPOPT_EOL		0
#define ARS_TCPOPT_NOP		1
#define ARS_TCPOPT_MAXSEG	2
#define ARS_TCPOPT_WINDOW	3
#define ARS_TCPOPT_SACK_PERM	4
#define ARS_TCPOPT_SACK		5
#define ARS_TCPOPT_ECHOREQUEST	6
#define ARS_TCPOPT_ECHOREPLY	7
#define ARS_TCPOPT_TIMESTAMP	8

#define ARS_TCP_TH_FIN	0x01
#define ARS_TCP_TH_SYN	0x02
#define ARS_TCP_TH_RST	0x04
#define ARS_TCP_TH_PUSH	0x08
#define ARS_TCP_TH_ACK	0x10
#define ARS_TCP_TH_URG	0x20
#define	ARS_TCP_TH_X 	0x40	/* X tcp flag */
#define ARS_TCP_TH_Y 	0x80	/* Y tcp flag */

/* ICMP TYPE */
#define ARS_ICMP_ECHOREPLY          0       /* Echo Reply                   */
#define ARS_ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#define ARS_ICMP_SOURCE_QUENCH      4       /* Source Quench                */
#define ARS_ICMP_REDIRECT           5       /* Redirect (change route)      */
#define ARS_ICMP_ECHO               8       /* Echo Request                 */
#define ARS_ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */
#define ARS_ICMP_PARAMETERPROB      12      /* Parameter Problem            */
#define ARS_ICMP_TIMESTAMP          13      /* Timestamp Request            */
#define ARS_ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply              */
#define ARS_ICMP_INFO_REQUEST       15      /* Information Request          */
#define ARS_ICMP_INFO_REPLY         16      /* Information Reply            */
#define ARS_ICMP_ADDRESS            17      /* Address Mask Request         */
#define ARS_ICMP_ADDRESSREPLY       18      /* Address Mask Reply           */

/* Codes for UNREACHABLE */
#define ARS_ICMP_UNR_NET		0       /* Network Unreachable */
#define ARS_ICMP_UNR_HOST		1       /* Host Unreachable */
#define ARS_ICMP_UNR_PROT		2       /* Protocol Unreachable */
#define ARS_ICMP_UNR_PORT		3       /* Port Unreachable */
#define ARS_ICMP_UNR_FRAG_NEEDED	4       /* Fragmentation Needed,DF set*/
#define ARS_ICMP_UNR_SR_FAILED          5       /* Source Route failed */
#define ARS_ICMP_UNR_UNK_NET		6
#define ARS_ICMP_UNR_UNK_HOST		7
#define ARS_ICMP_UNR_ISOLATED_HOST	8
#define ARS_ICMP_UNR_NET_ANO		9
#define ARS_ICMP_UNR_HOST_ANO		10
#define ARS_ICMP_UNR_NET_UNR_TOS	11
#define ARS_ICMP_UNR_HOST_UNR_TOS	12
#define ARS_ICMP_UNR_PKT_FILTERED	13      /* Packet filtered */
#define ARS_ICMP_UNR_PREC_VIOLATION	14      /* Precedence violation */
#define ARS_ICMP_UNR_PREC_CUTOFF	15      /* Precedence cut off */
#define ARS_NR_ICMP_UNREACH 15	/* Instead of hardcoded immediate value */

/* Codes for REDIRECT */
#define ARS_ICMP_REDIR_NET		0       /* Redirect Net */
#define ARS_ICMP_REDIR_HOST		1       /* Redirect Host */
#define ARS_ICMP_REDIR_NETTOS		2       /* Redirect Net for TOS */
#define ARS_ICMP_REDIR_HOSTTOS		3       /* Redirect Host for TOS */

/* Codes for TIME_EXCEEDED */
#define ARS_ICMP_EXC_TTL		0       /* TTL count exceeded */
#define ARS_ICMP_EXC_FRAGTIME		1       /* TTL exceeded reassembling */

/* IGRP defines */
#define ARS_IGRP_OPCODE_UPDATE		1
#define ARS_IGRP_OPCODE_REQUEST		2

/* The IP header structure */
struct ars_iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    ihl:4,
                version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                ihl:4;
#else
#error  "Please, edit Makefile and add -DBYTE_ORDER_(BIG|LITTLE)_ENDIAN"
#endif
        __u8    tos;
        __u16   tot_len;
        __u16   id;
        __u16   frag_off;
        __u8    ttl;
        __u8    protocol;
        __u16   check;
        __u32   saddr;
        __u32   daddr;
};

/* The IP options structure */
struct ars_ipopt {
	u_int8_t kind;
	u_int8_t len;
	union {
		struct {
			u_int16_t s;
			u_int16_t c;
			u_int16_t h;
			u_int8_t tcc[3];
		} sec;		/* security */
		struct {
			u_int8_t ptr;
			u_int8_t data[37];
		} src;		/* loose and strict source routing */
		struct {
			u_int8_t ptr;
			u_int8_t data[37];
		} rr;		/* record route */
		struct {
			u_int16_t id;
		} sid;		/* stream id */
		struct {
			u_int8_t ptr;
			u_int8_t flags;
			u_int8_t data[36];
		} ts;		/* timestamp */
	} un;
};

/* The UDP header structure */
struct ars_udphdr { 
	__u16 uh_sport;     /* source port */
	__u16 uh_dport;     /* destination port */
	__u16 uh_ulen;      /* udp length */
	__u16 uh_sum;       /* udp checksum */
};

/* The TCP header structure */
struct ars_tcphdr {
	__u16	th_sport;               /* source port */
	__u16	th_dport;               /* destination port */
	__u32	th_seq;                 /* sequence number */
	__u32	th_ack;                 /* acknowledgement number */
#if defined (__LITTLE_ENDIAN_BITFIELD)
	__u8    th_x2:4,                /* (unused) */
		th_off:4;               /* data offset */
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8    th_off:4,               /* data offset */
		th_x2:4;                /* (unused) */
#else
#error  "Please, edit Makefile and add -DBYTE_ORDER_(BIG|LITTLE)_ENDIAN"
#endif
	__u8    th_flags;
	__u16   th_win;                 /* window */
	__u16   th_sum;                 /* checksum */
	__u16   th_urp;                 /* urgent pointer */
};

/* The TCP options structure */
struct ars_tcpopt {
	u_int8_t kind;
	u_int8_t len;
	union {
		struct {
			u_int16_t size;
		} mss;
		struct {
			u_int8_t shift;
		} win;
		struct {
			u_int8_t origin[4];
			u_int8_t size[4];
		} sack[4]; /* max 4 SACK blocks in 40 bytes of space */
		struct {
			u_int8_t info[4];
		} echo;
		struct {
			u_int8_t tsval[4];
			u_int8_t tsecr[4];
		} timestamp;
	} un;
};

/* The ICMP header structure */
struct ars_icmphdr
{
	__u8          type;
	__u8          code;
	__u16         checksum;
	union
	{
		struct
		{
			__u16   id;
			__u16   sequence;
		} echo; /* called echo since it's the most used */
		__u32   gateway;
	} un;
};

/* TCP/UDP pseudo header used to compute the checksum */
struct ars_pseudohdr
{
	__u32 saddr;
	__u32 daddr;
	__u8  zero;
	__u8  protocol;
	__u16 lenght;
};

/* The IGRP header structure */
struct ars_igrphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    opcode:4,
                version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                opcode:4;
#else
#error  "Please, edit Makefile and add -DBYTE_ORDER_(BIG|LITTLE)_ENDIAN"
#endif
	__u8	edition;
	__u16	autosys;
	__u16	interior;
	__u16	system;
	__u16	exterior;
	__u16	checksum;
};

/* The IGRP entry */
struct ars_igrpentry {
	__u8	destination[3];
	__u8	delay[3];
	__u8	bandwidth[3];
	__u8	mtu[2];
	__u8	reliability;
	__u8	load;
	__u8	hopcount;
};

struct ars_packet; /* forward declaration */

/* ARS layer */
struct ars_layer {
	int l_type;
	int l_size;
	int l_flags;
	void *l_data;
	struct ars_packet *l_packet;
};

#define ARS_MAX_LAYER	256
#define ARS_ERR_BUFSZ	1024

/* Types */
#define ARS_TYPE_SIZE		32
#define ARS_TYPE_NULL		0
#define ARS_TYPE_IP		1
#define ARS_TYPE_IPOPT		2
#define ARS_TYPE_ICMP		3
#define ARS_TYPE_UDP		4
#define ARS_TYPE_TCP		5
#define ARS_TYPE_TCPOPT		6
#define ARS_TYPE_IGRP		7
#define ARS_TYPE_IGRPENTRY	8
#define ARS_TYPE_DATA		31

/* ARS packet context */
struct ars_packet {
	char *p_error;
	int p_layer_nr;
	struct ars_layer p_layer[ARS_MAX_LAYER];
	void *p_default[ARS_TYPE_SIZE];
	int p_options;
	int aux; /* Auxiliar variable for data exchange between functions */
	int aux_ipproto; /* This hold the ip->proto field seen in the last
			  IP datagram so that when the IP options processing
			  is done, the split-machine can continue with
			  the right state. */
};

/* Facility to check for flags */
#define ARS_TAKE(f,x)		(f & x)
#define ARS_DONTTAKE(f, x)	(!(f & x))
#define ARS_TAKE_NONE		0

/* IP layer flags */
#define ARS_TAKE_IP_VERSION	(1 << 0)
#define ARS_TAKE_IP_HDRLEN	(1 << 1)
#define ARS_TAKE_IP_TOTLEN	(1 << 2)
#define ARS_TAKE_IP_PROTOCOL	(1 << 3)
#define ARS_TAKE_IP_CKSUM	(1 << 4)

/* IP options layers flags */
#define ARS_TAKE_IPOPT_PTR	(1 << 0) /* for RR, LSRR, SSRR */

/* ICMP layer flags */
#define ARS_TAKE_ICMP_CKSUM	(1 << 0)

/* UDP layer flags */
#define ARS_TAKE_UDP_CKSUM	(1 << 0)
#define ARS_TAKE_UDP_LEN	(1 << 1)

/* TCP layer flags */
#define ARS_TAKE_TCP_HDRLEN	(1 << 0)
#define ARS_TAKE_TCP_CKSUM	(1 << 1)

/* IGRP layer flags */
#define ARS_TAKE_IGRP_CKSUM	(1 << 0)

/* Some function that acts on layer switch to the last layer with this */
#define ARS_LAST_LAYER		-1

/* Structure and defines needed to calculate the internet-like checksum
 * when the data is splitted in more not adjacent buffers */
#define ARS_MC_INIT     0
#define ARS_MC_UPDATE   1
#define ARS_MC_FINAL    2

struct mc_context {
	u_int32_t oddbyte_flag;
	u_int32_t old;
	u_int8_t oddbyte;
	u_int8_t pad;
};

/* ARS layer info structure */
struct ars_layer_info {
	char *li_name; /* NULL = unused slot */
	int (*li_compiler) (struct ars_packet *pkt, int layer); /* NULL = NOP */
	int (*li_rapd) (struct adbuf *dest, struct ars_packet *pkt, int layer);
	int layer_id;
};

/* ARS layer info table */
extern struct ars_layer_info ars_linfo[ARS_TYPE_SIZE];

/* ARS interface managment structure and defines */
#define ARS_IF_UP	(1 << 0)
#define ARS_IF_LOOP	(1 << 1)
#define ARS_IF_IPV4	(1 << 2)
#define ARS_IF_IPV6 	(1 << 3)
#define ARS_IF_MISCONF	(1 << 4)

#define ARS_IF_MAX_IFACE	16
#define ARS_IF_NAME_SIZE	32

/* iface type are obtained using libpcap to avoid efforts duplication */
struct ars_iface {
	char if_name[ARS_IF_NAME_SIZE];
	int if_mtu;
	int if_flags;
	char if_ipv4addr[ARS_INET_ADDRSTRLEN];
	char if_ipv6addr[ARS_INET6_ADDRSTRLEN];
};

/* Flags for packet splitting */
#define ARS_SPLIT_FTRUNC        (1 << 0)
#define ARS_SPLIT_FBADCKSUM     (1 << 1)

/* Ars packet options */
#define ARS_OPT_RAPD_HEXDATA	(1 << 0) /* Use hex format for RAPD data */

/* More macros */
#define ars_atou(x) strtoul(x, (char **) NULL, 0)
#define ars_set_option(pkt,opt) do { (pkt)->p_options |= (opt); } while(0)
#define ars_clear_option(pkt,opt) do { (pkt)->p_options &= ~(opt); } while(0)
#define ars_test_option(pkt,opt) ((pkt)->p_options & (opt))

/* Prototypes */
int ars_init(struct ars_packet *pkt);
int ars_destroy(struct ars_packet *pkt);
int ars_nospace(struct ars_packet *pkt);
int ars_add_generic(struct ars_packet *pkt, size_t size, int type);
void *ars_add_iphdr(struct ars_packet *pkt, int unused);
void *ars_add_ipopt(struct ars_packet *pkt, int option);
void *ars_add_udphdr(struct ars_packet *pkt, int unused);
void *ars_add_tcphdr(struct ars_packet *pkt, int unused);
void *ars_add_tcpopt(struct ars_packet *pkt, int option);
void *ars_add_icmphdr(struct ars_packet *pkt, int unused);
void *ars_add_igrphdr(struct ars_packet *pkt, int unused);
void *ars_add_igrpentry(struct ars_packet *pkt, int unused);
void *ars_add_data(struct ars_packet *pkt, int size);
size_t ars_relative_size(struct ars_packet *pkt, int layer_nr);
size_t ars_packet_size(struct ars_packet *pkt);
u_int16_t ars_cksum(void *vbuf, size_t nbytes);
u_int16_t ars_multi_cksum(struct mc_context *c, int op, void *vbuf, size_t nbytes);
int ars_compile(struct ars_packet *pkt);
int ars_udptcp_cksum(struct ars_packet *pkt, int layer, u_int16_t *sum);
int ars_open_rawsocket(struct ars_packet *pkt);
int ars_build_packet(struct ars_packet *pkt, unsigned char **packet, size_t *size);
int ars_bsd_fix(struct ars_packet *pkt, unsigned char *packet, size_t size);
int ars_set_flags(struct ars_packet *pkt, int layer, int flags);
int ars_send(int s, struct ars_packet *pkt, struct sockaddr *sa, socklen_t slen);
int ars_resolve(struct ars_packet *pkt, u_int32_t *dest, char *hostname);
int ars_set_error(struct ars_packet *pkt, const char *fmt, ...);
int ars_d_build(struct ars_packet *pkt, char *t);
int ars_valid_layer(int layer);
int ars_get_iface_list(struct ars_iface *iface, size_t *isize);
int ars_get_iface(char *name, struct ars_iface *i);
int ars_valid_layer(int layer);
int ars_remove_layer(struct ars_packet *pkt, int layer);

/* split.c prototypes */
int ars_seems_ip(struct ars_iphdr *ip, size_t size);
int ars_guess_ipoff(void *packet, size_t size, int *lhs);
int ars_check_ip_cksum(struct ars_iphdr *ip);
int ars_check_icmp_cksum(struct ars_icmphdr *icmp, size_t size);
int ars_split_packet(void *packet, size_t size, int ipoff, struct ars_packet *pkt);

/* reverse apd */
int ars_d_from_ars(char *dest, size_t len, struct ars_packet *pkt);
int ars_rapd_ip(struct adbuf *dest, struct ars_packet *pkt, int layer);
int ars_rapd_ipopt(struct adbuf *dest, struct ars_packet *pkt, int layer);
int ars_rapd_icmp(struct adbuf *dest, struct ars_packet *pkt, int layer);
int ars_rapd_udp(struct adbuf *dest, struct ars_packet *pkt, int layer);
int ars_rapd_tcp(struct adbuf *dest, struct ars_packet *pkt, int layer);
int ars_rapd_tcpopt(struct adbuf *dest, struct ars_packet *pkt, int layer);
int ars_rapd_igrp(struct adbuf *dest, struct ars_packet *pkt, int layer);
int ars_rapd_igrpentry(struct adbuf *dest, struct ars_packet *pkt, int layer);
int ars_rapd_data(struct adbuf *dest, struct ars_packet *pkt, int layer);

#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__) && \
    !defined(__bsdi__) && !defined(__APPLE__)
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#endif /* _ARS_H */
